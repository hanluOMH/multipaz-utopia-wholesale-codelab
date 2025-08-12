package org.multipaz.samples.wallet.cmp


import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.statement.readBytes
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.parameters
import io.ktor.http.protocolWithAuthority
import io.ktor.http.takeFrom
import io.ktor.util.encodeBase64
import io.ktor.utils.io.printStack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.asn1.OID
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.provision.AuthorizationChallenge
import org.multipaz.provision.AuthorizationResponse
import org.multipaz.provision.BindingKeyInfo
import org.multipaz.provision.KeyProofType
import org.multipaz.provision.ProvisioningMetadata
import org.multipaz.provision.openid4vci.Backend
import org.multipaz.provision.openid4vci.ClientPreferences
import org.multipaz.provision.openid4vci.Openid4VciProvisioningClient
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyAttestation
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaProvider
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.Storage
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.Logger
import org.multipaz.util.Platform
import org.multipaz.util.toBase64Url
import kotlin.reflect.KClass
import kotlin.reflect.cast
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * User data for OAuth form submission
 */
data class UserData(
    val givenName: String = "Given",
    val familyName: String = "Family",
    val birthDate: String = "1998-09-04"
)




/**
 * OpenID4VCI Enrollment Function
 *
 * This function demonstrates how to use the OpenID4VCI functionality using the
 * latest commit's Openid4VciProvisioningClient implementation.
 */
class OpenID4VCIEnrollment {

    object TestBackend: Backend {
        override suspend fun createJwtClientAssertion(tokenUrl: String): String {
            throw IllegalStateException()
        }

        @OptIn(ExperimentalTime::class)
        override suspend fun createJwtWalletAttestation(keyAttestation: KeyAttestation): String {
            // Implements this draft:
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-04

            val signatureAlgorithm = localAttestationPrivateKey.curve.defaultSigningAlgorithmFullySpecified
            val head = buildJsonObject {
                put("typ", "oauth-client-attestation+jwt")
                put("alg", signatureAlgorithm.joseAlgorithmIdentifier)
                put("x5c", buildJsonArray {
                    add(localAttestationCertificate.encodedCertificate.encodeBase64())
                })
            }.toString().encodeToByteArray().toBase64Url()

            val now = Clock.System.now()
            val notBefore = now - 1.seconds
            // Expiration here is only for the wallet assertion to be presented to the issuing server
            // in the given timeframe (which happens without user interaction). It does not imply that
            // the key becomes invalid at that point in time.
            val expiration = now + 5.minutes
            val payload = buildJsonObject {
                put("iss", localClientId)
                put("sub", testClientPreferences.clientId)
                put("exp", expiration.epochSeconds)
                put("cnf", buildJsonObject {
                    put("jwk", keyAttestation.publicKey.toJwk(
                        buildJsonObject {
                            put("kid", JsonPrimitive(testClientPreferences.clientId))
                        }
                    ))
                })
                put("nbf", notBefore.epochSeconds)
                put("iat", now.epochSeconds)
                put("wallet_name", "Multipaz Wallet")
                put("wallet_link", "https://multipaz.org")
            }.toString().encodeToByteArray().toBase64Url()

            val message = "$head.$payload"
            val sig = Crypto.sign(
                key = localAttestationPrivateKey,
                signatureAlgorithm = signatureAlgorithm,
                message = message.encodeToByteArray()
            )
            val signature = sig.toCoseEncoded().toBase64Url()

            return "$message.$signature"
        }

        @OptIn(ExperimentalTime::class)
        override suspend fun createJwtKeyAttestation(
            keyAttestations: List<KeyAttestation>,
            challenge: String
        ): String {
            // Generate key attestation
            val keyList = keyAttestations.map { it.publicKey }

            val alg = localAttestationPrivateKey.curve.defaultSigningAlgorithm.joseAlgorithmIdentifier
            val head = buildJsonObject {
                put("typ", "keyattestation+jwt")
                put("alg", alg)
                put("x5c", buildJsonArray {
                    add(localAttestationCertificate.encodedCertificate.encodeBase64())
                })
            }.toString().encodeToByteArray().toBase64Url()

            val now = Clock.System.now()
            val notBefore = now - 1.seconds
            val expiration = now + 5.minutes
            val payload = buildJsonObject {
                put("iss", localClientId)
                put("attested_keys", JsonArray(keyList.map { it.toJwk() }))
                put("nonce", challenge)
                put("nbf", notBefore.epochSeconds)
                put("exp", expiration.epochSeconds)
                put("iat", now.epochSeconds)
            }.toString().encodeToByteArray().toBase64Url()

            val message = "$head.$payload"
            val sig = Crypto.sign(
                key = localAttestationPrivateKey,
                signatureAlgorithm = localAttestationPrivateKey.curve.defaultSigningAlgorithm,
                message = message.encodeToByteArray()
            )
            val signature = sig.toCoseEncoded().toBase64Url()

            return "$message.$signature"
        }

        private val localAttestationCertificate = X509Cert.fromPem("""
                -----BEGIN CERTIFICATE-----
                MIIBxTCCAUugAwIBAgIJAOQTL9qcQopZMAoGCCqGSM49BAMDMDgxNjA0BgNVBAMT
                LXVybjp1dWlkOjYwZjhjMTE3LWI2OTItNGRlOC04ZjdmLTYzNmZmODUyYmFhNjAe
                Fw0yNDA5MjMyMjUxMzFaFw0zNDA5MjMyMjUxMzFaMDgxNjA0BgNVBAMTLXVybjp1
                dWlkOjYwZjhjMTE3LWI2OTItNGRlOC04ZjdmLTYzNmZmODUyYmFhNjB2MBAGByqG
                SM49AgEGBSuBBAAiA2IABN4D7fpNMAv4EtxyschbITpZ6iNH90rGapa6YEO/uhKn
                C6VpPt5RUrJyhbvwAs0edCPthRfIZwfwl5GSEOS0mKGCXzWdRv4GGX/Y0m7EYypo
                x+tzfnRTmoVX3v6OxQiapKMhMB8wHQYDVR0OBBYEFPqAK5EjiQbxFAeWt//DCaWt
                C57aMAoGCCqGSM49BAMDA2gAMGUCMEO01fJKCy+iOTpaVp9LfO7jiXcXksn2BA22
                reiR9ahDRdGNCrH1E3Q2umQAssSQbQIxAIz1FTHbZPcEbA5uE5lCZlRG/DQxlZhk
                /rZrkPyXFhqEgfMnQ45IJ6f8Utlg+4Wiiw==
                -----END CERTIFICATE-----
            """.trimIndent()
        )

        private val localAttestationPrivateKey = EcPrivateKey.fromPem("""
            -----BEGIN PRIVATE KEY-----
            ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDBn7jeRC9u9de3kOkrt9lLT
            Pvd1hflNq1FCgs7D+qbbwz1BQa4XXU0SjsV+R1GjnAY=
            -----END PRIVATE KEY-----
            """.trimIndent(),
            localAttestationCertificate.ecPublicKey
        )

        private val localClientId =
            localAttestationCertificate.subject.components[OID.COMMON_NAME.oid]?.value
                ?: throw IllegalStateException("No common name (CN) in certificate's subject")
    }



    object TestBackendEnvironment: BackendEnvironment {
        override fun <T : Any> getInterface(clazz: KClass<T>): T {
            return clazz.cast(when (clazz) {
                Storage::class -> storage
                HttpClient::class -> httpClient
                Backend::class -> TestBackend
                SecureAreaProvider::class -> secureAreaProvider
                else -> throw IllegalArgumentException("no such class available: ${clazz.simpleName}")
            })
        }
    }

    companion object {
        private const val TAG = "OpenID4VCIEnrollment"
        @OptIn(ExperimentalTime::class)
        val storage = EphemeralStorage()
        val secureAreaProvider = SecureAreaProvider<SecureArea>(Dispatchers.Default) {
            SoftwareSecureArea.create(storage)
        }

        val testClientPreferences = ClientPreferences(
            clientId = "urn:uuid:418745b8-78a3-4810-88df-7898aff3ffb4",
            redirectUrl = "https://apps.multipaz.org",
            locales = listOf("en-US"),
            signingAlgorithms = listOf(Algorithm.ESP256)
        )
        /**
         * Default client preferences for OpenID4VCI
         */
        private val defaultClientPreferences = ClientPreferences(
            clientId = "urn:uuid:418745b8-78a3-4810-88df-7898aff3ffb4",
            redirectUrl = "https://apps.multipaz.org",
            locales = listOf("en-US"),
            signingAlgorithms = listOf(Algorithm.ESP256)
        )



        /**
         * HTTP client for form submissions
         */
        private val httpClient = HttpClient() {
            followRedirects = false
        }

        /**
         * Process an OpenID4VCI credential offer URL and initiate enrollment
         *
         * @param credentialOfferUrl The OpenID4VCI credential offer URL
         * @param clientPreferences Optional client preferences (uses default if null)
         * @param onSuccess Callback when enrollment is successful
         * @param onError Callback when enrollment fails
         */
        suspend fun processCredentialOffer(
            credentialOfferUrl: String,
            clientPreferences: ClientPreferences? = null,
            onSuccess: (Openid4VciProvisioningClient) -> Unit,
            onError: (Throwable) -> Unit
        ) {
            try {
                Logger.i(TAG, "Processing credential offer: $credentialOfferUrl")

                // Use provided client preferences or default
                val preferences = clientPreferences ?: defaultClientPreferences

                // Create the OpenID4VCI client directly
                val client = Openid4VciProvisioningClient.createFromOffer(
                    offerUri = credentialOfferUrl,
                    clientPreferences = preferences
                )

                Logger.i(TAG, "Successfully created OpenID4VCI client")

                // Call success callback with the client
                onSuccess(client)

            } catch (e: Exception) {
                Logger.e(TAG, "Error processing credential offer", e)
                onError(e)
            }
        }

        /**
         * Complete OpenID4VCI enrollment flow with proper OAuth handling
         *
         * @param credentialOfferUrl The OpenID4VCI credential offer URL
         * @param clientPreferences Optional client preferences
         * @param userData Optional user data for OAuth form (uses defaults if null)
         * @param onSuccess Callback when enrollment completes successfully
         * @param onError Callback when enrollment fails
         */
        suspend  fun enrollCredential(
            credentialOfferUrl: String,
            clientPreferences: ClientPreferences? = null,
            userData: UserData = UserData(),
            onSuccess: (List<ByteArray>) -> Unit,
            onError: (Throwable) -> Unit
        ) {
            try {
                // Process credential offer
                val preferences = clientPreferences ?: defaultClientPreferences
                val client = Openid4VciProvisioningClient.createFromOffer(
                    offerUri = credentialOfferUrl,
                    clientPreferences = preferences
                )

                Logger.i(TAG, "Starting OpenID4VCI enrollment flow")

                // Get authorization challenges
                val challenges = client.getAuthorizationChallenges()
                Logger.i(TAG, "Got ${challenges.size} authorization challenges")

                if (challenges.isNotEmpty()) {
                    // Handle OAuth flow - similar to the test
                    val oauthChallenge = challenges.first() as AuthorizationChallenge.OAuth
                    Logger.i(TAG, "OAuth authorization required: ${oauthChallenge.url}")

                    // Handle OAuth flow with form submission
                    val authorizationResponse = handleOAuthFormSubmission(
                        oauthChallenge,
                        preferences,
                        userData
                    )
                    client.authorize(authorizationResponse)
                    Logger.i(TAG, "OAuth authorization completed")
                }

                // Get metadata to determine credential type and handle key binding properly
                val metadata = client.getMetadata()
                val credentialConfiguration = metadata.credentials[client.credentialOffer.configurationId]!!

                val bindingKeyInfo = if (credentialConfiguration.keyProofType == KeyProofType.Keyless) {
                    Logger.i(TAG, "Using keyless binding")
                    BindingKeyInfo.Keyless
                } else {
                    // For non-keyless credentials, get challenge and create attestation
                    val keyChallenge = client.getKeyBindingChallenge()
                    Logger.i(TAG, "Got key binding challenge: $keyChallenge")

                    // Create key attestation using platform SecureArea (Android Keystore on Android)
                    val secureArea = Platform.getSecureArea()
                    val keyInfo = secureArea.createKey(
                        alias = null,
                        createKeySettings = CreateKeySettings(
                            nonce = keyChallenge.encodeToByteString()
                        )
                    )

                    Logger.i(TAG, "Created key attestation for binding")
                    BindingKeyInfo.Attestation(listOf(keyInfo.attestation))
                }

                // Obtain credentials
                val credentials = client.obtainCredentials(bindingKeyInfo)
                Logger.i(TAG, "Successfully obtained ${credentials.size} credentials")

                // Convert to ByteArray for the callback
                val credentialBytes = credentials.map { it.toByteArray() }
                onSuccess(credentialBytes)

            } catch (e: Exception) {
                Logger.e(TAG, "Error during enrollment flow", e)
                onError(e)
            }
        }

        /**
         * Handle OAuth form submission similar to ProvisioningClientTest
         *
         * @param oauthChallenge The OAuth challenge
         * @param clientPreferences Client preferences for redirect URL
         * @param userData User data for form submission (uses defaults if null)
         * @return AuthorizationResponse with the authorization code
         */
        private suspend fun handleOAuthFormSubmission(
            oauthChallenge: AuthorizationChallenge.OAuth,
            clientPreferences: ClientPreferences,
            userData: UserData? = null
        ): AuthorizationResponse {
            val authorizationUrl = Url(oauthChallenge.url)

            // Extract the authorization code from the authorization page
            val request = httpClient.get(authorizationUrl) {}
            if (request.status != HttpStatusCode.OK) {
                throw IllegalStateException("Failed to get authorization page: ${request.status}")
            }

            val authText = request.readBytes().decodeToString()
            val pattern = "name=\"authorizationCode\" value=\""
            val index = authText.indexOf(pattern)
            if (index == -1) {
                throw IllegalStateException("Could not find authorization code in response")
            }

            val first = index + pattern.length
            val last = authText.indexOf('"', first)
            val authorizationCode = authText.substring(first, last)

            Logger.i(TAG, "Extracted authorization code from form")

            // Use provided user data or defaults
            val formData = userData ?: UserData()

            // Submit the form with user data
            var formRequest = httpClient.submitForm(
                url = authorizationUrl.protocolWithAuthority + authorizationUrl.encodedPath,
                formParameters = parameters {
                    append("authorizationCode", authorizationCode)
                    append("given_name", formData.givenName)
                    append("family_name", formData.familyName)
                    append("birth_date", formData.birthDate)
                }
            )

            // Follow redirects until we get to our redirect URL
            var location: String = ""
            while (formRequest.status == HttpStatusCode.Found) {
                location = formRequest.headers["Location"]!!
                if (location.startsWith(clientPreferences.redirectUrl)) {
                    break
                }
                val newUrl = URLBuilder(authorizationUrl).takeFrom(location).build()
                formRequest = httpClient.get(newUrl)
            }

            Logger.i(TAG, "OAuth form submission completed, redirect URL: $location")

            // Create authorization response
            return AuthorizationResponse.OAuth(
                id = oauthChallenge.id,
                parameterizedRedirectUrl = location
            )
        }

        /**
         * Handle OAuth authorization flow
         *
         * @param client The OpenID4VCI client
         * @param authorizationUrl The authorization URL to open
         * @param userData Optional user data for form submission
         * @param onAuthorizationComplete Callback when authorization is complete
         * @param onError Callback when authorization fails
         */
        suspend fun handleOAuthFlow(
            client: Openid4VciProvisioningClient,
            authorizationUrl: String,
            userData: UserData? = null,
            onAuthorizationComplete: (AuthorizationResponse) -> Unit,
            onError: (Throwable) -> Unit
        ) {
            try {
                Logger.i(TAG, "Starting OAuth flow with URL: $authorizationUrl")

                // Get authorization challenges
                val challenges = client.getAuthorizationChallenges()
                if (challenges.isEmpty()) {
                    throw IllegalStateException("No authorization challenges available")
                }

                val oauthChallenge = challenges.first() as AuthorizationChallenge.OAuth

                // Handle OAuth form submission
                val authorizationResponse = handleOAuthFormSubmission(
                    oauthChallenge,
                    defaultClientPreferences,
                    userData
                )
                onAuthorizationComplete(authorizationResponse)

            } catch (e: Exception) {
                Logger.e(TAG, "Error in OAuth flow", e)
                onError(e)
            }
        }

        /**
         * Get metadata for a credential offer without starting enrollment
         *
         * @param credentialOfferUrl The OpenID4VCI credential offer URL
         * @param clientPreferences Optional client preferences
         * @param onSuccess Callback with metadata information
         * @param onError Callback when operation fails
         */
        suspend  fun getCredentialMetadata(
            credentialOfferUrl: String,
            clientPreferences: ClientPreferences? = null,
            onSuccess: (ProvisioningMetadata) -> Unit,
            onError: (Throwable) -> Unit
        ) {
            try {
                val preferences = clientPreferences ?: defaultClientPreferences
                val client = Openid4VciProvisioningClient.createFromOffer(
                    offerUri = credentialOfferUrl,
                    clientPreferences = preferences
                )

                val metadata = client.getMetadata()
                Logger.i(TAG, "Got metadata for ${metadata.credentials.size} credentials")

                // Log credential details
                metadata.credentials.forEach { (id, credential) ->
                    Logger.i(TAG, "Credential ID: $id")
                    Logger.i(TAG, "  Format: ${credential.format}")
                    Logger.i(TAG, "  Key Proof Type: ${credential.keyProofType}")
                    Logger.i(TAG, "  Display: ${credential.display}")
                }

                onSuccess(metadata)
            } catch (e: Exception) {
                Logger.e(TAG, "Error getting metadata", e)
                onError(e)
            }
        }

        /**
         * Handle deep link with OpenID4VCI enrollment
         *
         * @param deepLinkUrl The deep link URL containing the credential offer
         * @param clientPreferences Optional client preferences
         * @param userData Optional user data for OAuth form
         * @param onSuccess Callback when enrollment is successful
         * @param onError Callback when enrollment fails
         */
        suspend  fun handleDeepLink(
            deepLinkUrl: String,
            clientPreferences: ClientPreferences? = defaultClientPreferences,
            userData: UserData? = null,
            onSuccess: (List<ByteArray>) -> Unit,
            onError: (Throwable) -> Unit
        ) {
            // Check if this is an OpenID4VCI credential offer
            if (deepLinkUrl.startsWith("openid-credential-offer://")) {
                Logger.i(TAG, "Processing OpenID4VCI deep link: $deepLinkUrl")
                enrollCredential(
                    credentialOfferUrl = deepLinkUrl,
                    clientPreferences = clientPreferences,
                    userData =  createUserData("John","Lee","1998-09-04"),
                    onSuccess = onSuccess,
                    onError = onError
                )
            } else {
                Logger.d(TAG, "Not an OpenID4VCI deep link: $deepLinkUrl")
            }
        }

        suspend fun handleDeepLink(url: String, processCredentials: suspend (List<ByteArray>) -> Unit){
            withContext(TestBackendEnvironment){
                handleDeepLink(
                    deepLinkUrl = url,
                    onSuccess = { list ->
                        // Defer storage/processing to caller-provided function
                        CoroutineScope(Dispatchers.Default).launch {
                            processCredentials(list)
                        }
                    },
                    onError = { e ->
                        e.printStack()
                    }
                )
            }
        }
        /**
         * Handle QR code scan with OpenID4VCI enrollment
         *
         * @param qrCodeData The QR code data containing the credential offer
         * @param clientPreferences Optional client preferences
         * @param userData Optional user data for OAuth form
         * @param onSuccess Callback when enrollment is successful
         * @param onError Callback when enrollment fails
         */
        suspend  fun handleQRCode(
            qrCodeData: String,
            clientPreferences: ClientPreferences? = null,
            userData: UserData? = null,
            onSuccess: (List<ByteArray>) -> Unit,
            onError: (Throwable) -> Unit
        ) {
            Logger.i(TAG, "Processing QR code data: $qrCodeData")
            enrollCredential(
                credentialOfferUrl = qrCodeData,
                clientPreferences = clientPreferences,
                userData = createUserData("John","Lee","1998-09-04"),
                onSuccess = onSuccess,
                onError = onError
            )
        }

        /**
         * Create custom client preferences
         *
         * @param clientId Your client ID
         * @param redirectUrl Your redirect URL
         * @param locales List of preferred locales
         * @param signingAlgorithms List of supported signing algorithms
         */
        fun createClientPreferences(
            clientId: String,
            redirectUrl: String,
            locales: List<String> = listOf("en-US"),
            signingAlgorithms: List<Algorithm> = listOf(Algorithm.ESP256)
        ): ClientPreferences {
            return ClientPreferences(
                clientId = clientId,
                redirectUrl = redirectUrl,
                locales = locales,
                signingAlgorithms = signingAlgorithms
            )
        }

        /**
         * Create custom user data for OAuth form submission
         *
         * @param givenName User's given name
         * @param familyName User's family name
         * @param birthDate User's birth date (YYYY-MM-DD format)
         */
        fun createUserData(
            givenName: String,
            familyName: String,
            birthDate: String
        ): UserData {
            return UserData(
                givenName = givenName,
                familyName = familyName,
                birthDate = birthDate
            )
        }
    }
}

