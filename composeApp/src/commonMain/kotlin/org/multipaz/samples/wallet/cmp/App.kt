package org.multipaz.samples.wallet.cmp

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.ktor.utils.io.core.toByteArray
import io.ktor.utils.io.printStack
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import utopiasample.composeapp.generated.resources.Res
import utopiasample.composeapp.generated.resources.compose_multiplatform
import org.jetbrains.compose.resources.painterResource
import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Simple
import org.multipaz.compose.permissions.rememberBluetoothPermissionState
import org.multipaz.compose.presentment.Presentment
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.compose.qrcode.generateQrCode
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.engagement.EngagementGenerator
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.transport.MdocTransportFactory
import org.multipaz.mdoc.transport.MdocTransportOptions
import org.multipaz.mdoc.transport.advertise
import org.multipaz.mdoc.transport.waitForConnection
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.models.digitalcredentials.DigitalCredentials
import org.multipaz.models.presentment.MdocPresentmentMechanism
import org.multipaz.models.presentment.PresentmentModel
import org.multipaz.models.presentment.PresentmentSource
import org.multipaz.models.presentment.SimplePresentmentSource
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustPoint
import org.multipaz.util.Platform
import org.multipaz.util.UUID
import org.multipaz.util.fromHex
import org.multipaz.util.toBase64Url
import kotlin.time.Duration.Companion.days
import utopiasample.composeapp.generated.resources.profile
import org.jetbrains.compose.resources.getDrawableResourceBytes
import org.jetbrains.compose.resources.getSystemResourceEnvironment
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.util.Logger
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.multipaz.util.fromBase64Url
import org.multipaz.sdjwt.SdJwt
import org.multipaz.mdoc.mso.StaticAuthDataParser
import org.multipaz.cbor.Cbor
import org.multipaz.mdoc.mso.MobileSecurityObjectParser
import org.multipaz.sdjwt.credential.KeylessSdJwtVcCredential
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.trustmanagement.TrustManagerLocal
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustPointAlreadyExistsException
import org.multipaz.securearea.CreateKeySettings as SA_CreateKeySettings

/**
 * Application singleton.
 *
 * Use [App.Companion.getInstance] to get an instance.
 */
class App() {
    lateinit var storage: Storage
    lateinit var documentTypeRepository: DocumentTypeRepository
    lateinit var secureAreaRepository: SecureAreaRepository
    lateinit var secureArea: SecureArea
    lateinit var documentStore: DocumentStore
    lateinit var readerTrustManager: TrustManager
    lateinit var presentmentModel: PresentmentModel
    lateinit var presentmentSource: PresentmentSource

    private val initLock = Mutex()
    private var initialized = false

    val appName = "UtopiaSample"
    val appIcon = Res.drawable.profile

    @OptIn(ExperimentalTime::class)
    suspend fun init() {
        initLock.withLock {
            if (initialized) {
                return
            }
            storage = Platform.nonBackedUpStorage
            secureArea = Platform.getSecureArea()
            secureAreaRepository = SecureAreaRepository.Builder().add(secureArea).build()
            documentTypeRepository = DocumentTypeRepository().apply {
                addDocumentType(DrivingLicense.getDocumentType())
            }
            documentStore = buildDocumentStore(storage = storage, secureAreaRepository = secureAreaRepository) {}
            if (documentStore.listDocuments().isEmpty()) {
                Logger.i(appName,"create document")
//                val now = Clock.System.now()
//                val signedAt = now
//                val validFrom = now
//                val validUntil = now + 365.days
//                val iacaCert = X509Cert.fromPem(
//                    getIaca_Cert()
//                )
//                Logger.i(appName, iacaCert.toPem())
//                val iacaKey = EcPrivateKey.fromPem(
//                    iaca_private_key,
//                    iacaCert.ecPublicKey
//                )
//                val dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
//                val dsCert = MdocUtil.generateDsCertificate(
//                    iacaCert = iacaCert,
//                    iacaKey = iacaKey,
//                    dsKey = dsKey.publicKey,
//                    subject = X500Name.fromName(name = "CN=Test DS Key"),
//                    serial = ASN1Integer.fromRandom(numBits = 128),
//                    validFrom = validFrom,
//                    validUntil = validUntil
//                )
                val profile = ByteString(
                    getDrawableResourceBytes(
                        getSystemResourceEnvironment(),
                        Res.drawable.profile,
                    )
                )
                val document = documentStore.createDocument(
                    displayName ="Tom Lee's Utopia Membership",
                    typeDisplayName = "Membership Card",
                    cardArt = profile,
                    other = UtopiaMemberInfo().toJsonString().encodeToByteString(),
                )
//                val mdocCredential =
//                    DrivingLicense.getDocumentType().createMdocCredentialWithSampleData(
//                        document = document,
//                        secureArea = secureArea,
//                        createKeySettings = CreateKeySettings(
//                            algorithm = Algorithm.ESP256,
//                            nonce = "Challenge".encodeToByteString(),
//                            userAuthenticationRequired = true
//                        ),
//                        dsKey = dsKey,
//                        dsCertChain = X509CertChain(listOf(dsCert)),
//                        signedAt = signedAt,
//                        validFrom = validFrom,
//                        validUntil = validUntil,
//                    )
            }else{
                Logger.i(appName,"document already exists")
            }
            presentmentModel = PresentmentModel().apply { setPromptModel(promptModel) }

            val tm = TrustManagerLocal(storage = storage, identifier = "reader")
            try {
                tm.addX509Cert(
                    certificate = X509Cert.fromPem(getReader_Root_Cert().trimIndent().trim()),
                    metadata = TrustMetadata(
                        displayName = "Multipaz Verifier",
                        displayIcon = null,
                        privacyPolicyUrl = "https://apps.multipaz.org",
                        testOnly = true
                    )
                )
            }catch (e: TrustPointAlreadyExistsException){
                e.printStack()
            }
// Or, if you have a Signed VICAL bytes:
// tm.addVical(encodedSignedVical = ByteString(vicalBytes), metadata = TrustMetadata(displayName = "VICAL Source"))

            readerTrustManager = tm

//            readerTrustManager = TrustManager().apply {
//                addTrustPoint(
//                    TrustPoint(
//                        certificate = X509Cert.fromPem(
//                            getReader_Root_Cert().trimIndent().trim()
//                        ),
//                        displayName = "OWF Multipaz TestApp",
//                        displayIcon = null,
//                        privacyPolicyUrl = "https://apps.multipaz.org"
//                    )
//                )
//                addTrustPoint(
//                    TrustPoint(
//                        certificate = X509Cert(
//                            "30820269308201efa0030201020210b7352f14308a2d40564006785270b0e7300a06082a8648ce3d0403033037310b300906035504060c0255533128302606035504030c1f76657269666965722e6d756c746970617a2e6f726720526561646572204341301e170d3235303631393232313633325a170d3330303631393232313633325a3037310b300906035504060c0255533128302606035504030c1f76657269666965722e6d756c746970617a2e6f7267205265616465722043413076301006072a8648ce3d020106052b81040022036200046baa02cc2f2b7c77f054e9907fcdd6c87110144f07acb2be371b2e7c90eb48580c5e3851bcfb777c88e533244069ff78636e54c7db5783edbc133cc1ff11bbabc3ff150f67392264c38710255743fee7cde7df6e55d7e9d5445d1bde559dcba8a381bf3081bc300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff02010030560603551d1f044f304d304ba049a047864568747470733a2f2f6769746875622e636f6d2f6f70656e77616c6c65742d666f756e646174696f6e2d6c6162732f6964656e746974792d63726564656e7469616c2f63726c301d0603551d0e04160414b18439852f4a6eeabfea62adbc51d081f7488729301f0603551d23041830168014b18439852f4a6eeabfea62adbc51d081f7488729300a06082a8648ce3d040303036800306502302a1f3bb0afdc31bcee73d3c5bf289245e76bd91a0fd1fb852b45fc75d3a98ba84430e6a91cbfc6b3f401c91382a43a64023100db22d2243644bb5188f2e0a102c0c167024fb6fe4a1d48ead55a6893af52367fb3cdbd66369aa689ecbeb5c84f063666".fromHex()
//                        ),
//                        displayName = "Multipaz Verifier",
//                        displayIcon = null,
//                        privacyPolicyUrl = "https://apps.multipaz.org"
//                    )
//                )
//            }
            presentmentSource = SimplePresentmentSource(
                documentStore = documentStore,
                documentTypeRepository = documentTypeRepository,
                readerTrustManager = readerTrustManager,
                preferSignatureToKeyAgreement = true,
                // Match domains used when storing credentials via OpenID4VCI
                domainMdocSignature = "openid4vci",
                domainMdocKeyAgreement = "openid4vci",
                domainKeylessSdJwt = "openid4vci",
                domainKeyBoundSdJwt = "openid4vci",
            )
            if (DigitalCredentials.Default.available) {
                //The credentials will still exist in your document store and can be used for other presentation mechanisms like proximity sharing (NFC/BLE), but they won't be accessible through the standardized digital credentials infrastructure that Android provides.
                DigitalCredentials.Default.startExportingCredentials(
                    documentStore = documentStore,
                    documentTypeRepository = documentTypeRepository
                )
            }
            initialized = true
        }
    }

    @Composable
    fun Content() {
        var isInitialized = remember { mutableStateOf<Boolean>(false) }
        if (!isInitialized.value) {
            CoroutineScope(Dispatchers.Main).launch {
                init()
                isInitialized.value = true
            }
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(text = "Initializing...")
            }
            return
        }

        MaterialTheme {
            MainApp()
        }
    }

    @Composable
    private fun MainApp() {
        val selectedTab = remember { mutableStateOf(0) }
        val tabs = listOf("Explore", "Account")
        val deviceEngagement = remember { mutableStateOf<ByteString?>(null) }
        
        Scaffold(
            bottomBar = {
                TabRow(
                    selectedTabIndex = selectedTab.value,
                    modifier = Modifier.background(Color.White)
                ) {
                    tabs.forEachIndexed { index, title ->
                        Tab(
                            selected = selectedTab.value == index,
                            onClick = { selectedTab.value = index },
                            text = { Text(title) },
                            icon = {
                                Icon(
                                    imageVector = if (index == 0) Icons.Default.Explore else Icons.Default.AccountCircle,
                                    contentDescription = title,
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                        )
                    }
                }
            }
        ) { paddingValues ->
            when (selectedTab.value) {
                0 -> ExploreScreen(modifier = Modifier.padding(paddingValues))
                1 -> AccountScreen(modifier = Modifier.padding(paddingValues), deviceEngagement = deviceEngagement)
            }
        }
    }

    @Composable
    private fun AccountScreen(modifier: Modifier = Modifier, deviceEngagement: MutableState<ByteString?>) {
        Column(
            modifier = modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            PromptDialogs(promptModel)
            Spacer(modifier = Modifier.height(30.dp))
            MembershipCard()
        }
        val coroutineScope = rememberCoroutineScope { promptModel }
        val blePermissionState = rememberBluetoothPermissionState()

        if (!blePermissionState.isGranted) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Button(
                    onClick = {
                        coroutineScope.launch {
                            blePermissionState.launchPermissionRequest()
                        }
                    }
                ) {
                    Text("Request BLE permissions")
                }
            }
        } else {
            val state = presentmentModel.state.collectAsState()
            when (state.value) {
                PresentmentModel.State.IDLE -> {
                    showQrButton(deviceEngagement)
                }

                PresentmentModel.State.CONNECTING -> {
                    showQrCode(deviceEngagement)
                }

                PresentmentModel.State.WAITING_FOR_SOURCE,
                PresentmentModel.State.PROCESSING,
                PresentmentModel.State.WAITING_FOR_DOCUMENT_SELECTION,
                PresentmentModel.State.WAITING_FOR_CONSENT,
                PresentmentModel.State.COMPLETED -> {
                    Presentment(
                        appName = appName,
                        appIconPainter = painterResource(appIcon),
                        presentmentModel = presentmentModel,
                        presentmentSource = presentmentSource,
                        documentTypeRepository = documentTypeRepository,
                        onPresentmentComplete = {
                            presentmentModel.reset()
                        },
                    )
                }
            }
        }
    }

    @Composable
    private fun showQrButton(showQrCode: MutableState<ByteString?>) {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(onClick = {
                presentmentModel.reset()
                presentmentModel.setConnecting()
                presentmentModel.presentmentScope.launch() {
                    val connectionMethods = listOf(
                        MdocConnectionMethodBle(
                            supportsPeripheralServerMode = false,
                            supportsCentralClientMode = true,
                            peripheralServerModeUuid = null,
                            centralClientModeUuid = UUID.randomUUID(),
                        )
                    )
                    val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
                    val advertisedTransports = connectionMethods.advertise(
                        role = MdocRole.MDOC,
                        transportFactory = MdocTransportFactory.Default,
                        options = MdocTransportOptions(bleUseL2CAP = true),
                    )
                    val engagementGenerator = EngagementGenerator(
                        eSenderKey = eDeviceKey.publicKey,
                        version = "1.0"
                    )
                    engagementGenerator.addConnectionMethods(advertisedTransports.map {
                        it.connectionMethod
                    })
                    val encodedDeviceEngagement = ByteString(engagementGenerator.generate())
                    showQrCode.value = encodedDeviceEngagement
                    val transport = advertisedTransports.waitForConnection(
                        eSenderKey = eDeviceKey.publicKey,
                        coroutineScope = presentmentModel.presentmentScope
                    )
                    presentmentModel.setMechanism(
                        MdocPresentmentMechanism(
                            transport = transport,
                            eDeviceKey = eDeviceKey,
                            encodedDeviceEngagement = encodedDeviceEngagement,
                            handover = Simple.NULL,
                            engagementDuration = null,
                            allowMultipleRequests = false
                        )
                    )
                    showQrCode.value = null
                }
            }) {
                Text("Present mDL via QR")
            }
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "The mDL is also available\n" +
                        "via NFC engagement and W3C DC API\n" +
                        "(Android-only right now)",
                textAlign = TextAlign.Center)
        }
    }

    @Composable
    private fun showQrCode(deviceEngagement: MutableState<ByteString?>) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (deviceEngagement.value != null) {
                val mdocUrl = "mdoc:" + deviceEngagement.value!!.toByteArray().toBase64Url()
                val qrCodeBitmap = remember { generateQrCode(mdocUrl) }
                Spacer(modifier = Modifier.height(128.dp))
                Text(text = "Present QR code to mdoc reader")
                Image(
                    modifier = Modifier.fillMaxWidth(),
                    bitmap = qrCodeBitmap,
                    contentDescription = null,
                    contentScale = ContentScale.FillWidth
                )
                Button(
                    onClick = {
                        presentmentModel.reset()
                    }
                ) {
                    Text("Cancel")
                }
            }
        }
    }


    /**
     * Handle a link (either a app link, universal link, or custom URL schema link).
     */
    fun handleUrl(url: String) {
        //TODO
        CoroutineScope(Dispatchers.IO).launch {
            // Initialize the backend provider and pass storage callback
            OpenID4VCIEnrollment.handleDeepLink(url) { creds ->
                storeIssuedCredentialsRaw(creds)
            }
        }



    }

    /**
     * Store issued credentials returned by OpenID4VCI enrollment into the existing document.
     * Accepts raw credential bytes as returned by client.obtainCredentials().
     */
    @OptIn(ExperimentalTime::class)
    suspend fun storeIssuedCredentialsRaw(credentialBytesList: List<ByteArray>) {
        if (documentStore.listDocuments().isEmpty()) {
            Logger.w(appName, "No document available to store credentials")
            return
        }

        // If the first document already has any credentials, skip storing to avoid duplicates
        val documentId = documentStore.listDocuments().first()
        val document = documentStore.lookupDocument(documentId) ?: return
        if (document.getCredentials().isNotEmpty()) {
            Logger.i(appName, "Document $documentId already has credentials; skipping store")
            return
        }
        val domain = "openid4vci"

        // Build a normalized response-like Json for logging consistency
        val responseJson = buildJsonObject {
            put("credentials", buildJsonArray {
                credentialBytesList.forEach { rawBytes ->
                    val asString = try {
                        val text = rawBytes.decodeToString()
                        val dotCount = text.count { it == '.' }
                        val printable = text.all { ch ->
                            val c = ch.code
                            (c in 32..126) || ch == '\n' || ch == '\r' || ch == '\t'
                        }
                        if (printable && dotCount >= 2) text else rawBytes.toBase64Url()
                    } catch (_: Throwable) {
                        rawBytes.toBase64Url()
                    }
                    add(buildJsonObject { put("credential", JsonPrimitive(asString)) })
                }
            })
        }
        Logger.i(appName, "Issuer response: $responseJson")

        val jsonArray = (responseJson["credentials"] as JsonArray)
        Logger.i(appName, "Normalized credentials array size: ${jsonArray.size}")
        jsonArray.forEachIndexed { index, element ->
            Logger.i(appName, "credentials[$index]: $element")
        }
        var storedCount = 0
        jsonArray.forEach { item ->
            val credentialString = item.jsonObject["credential"]!!.jsonPrimitive.content
            // Try SD-JWT first
            val stored = runCatching {
                val sdJwt = SdJwt(credentialString)
                val vct = "unknown"
                val cred = KeylessSdJwtVcCredential.create(
                    document = document,
                    asReplacementForIdentifier = null,
                    domain = domain,
                    vct = vct
                )
                cred.certify(
                    issuerProvidedAuthenticationData = credentialString.encodeToByteArray(),
                    validFrom = sdJwt.validFrom ?: sdJwt.issuedAt ?: Clock.System.now(),
                    validUntil = sdJwt.validUntil ?: kotlin.time.Instant.DISTANT_FUTURE
                )
                true
            }.getOrElse {
                false
            }
            if (stored) {
                storedCount += 1
                return@forEach
            }

            // Try mdoc (IssuerSigned base64url)
            runCatching {
                val credentialBytes = credentialString.fromBase64Url()
                val staticAuth = StaticAuthDataParser(credentialBytes).parse()
                val issuerAuthCoseSign1 = Cbor.decode(staticAuth.issuerAuth).asCoseSign1
                val encodedMsoBytes = Cbor.decode(issuerAuthCoseSign1.payload!!)
                val encodedMso = Cbor.encode(encodedMsoBytes.asTaggedEncodedCbor)
                val mso = MobileSecurityObjectParser(encodedMso).parse()

                val mdocCred = MdocCredential.create(
                    document = document,
                    asReplacementForIdentifier = null,
                    domain = domain,
                    secureArea = secureArea,
                    docType = mso.docType,
                    createKeySettings = SA_CreateKeySettings(
                        nonce = "Enroll".encodeToByteString()
                    )
                )
                mdocCred.certify(
                    issuerProvidedAuthenticationData = credentialBytes,
                    validFrom = mso.validFrom,
                    validUntil = mso.validUntil
                )
                storedCount += 1
            }.onFailure { e ->
                Logger.w(appName, "Skipping unknown credential format: ${e.message}")
            }
        }
        Logger.i(appName, "Stored $storedCount credential(s) into document $documentId")
    }

    companion object {
        val promptModel = Platform.promptModel

        private var app: App? = null
        fun getInstance(): App {
            if (app == null) {
                app = App()
            }
            return app!!
        }
    }
}