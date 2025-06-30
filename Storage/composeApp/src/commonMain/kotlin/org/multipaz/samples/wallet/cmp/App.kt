package org.multipaz.samples.wallet.cmp

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import utopiasample.composeapp.generated.resources.Res
import utopiasample.composeapp.generated.resources.profile
import org.jetbrains.compose.resources.getDrawableResourceBytes
import org.jetbrains.compose.resources.getSystemResourceEnvironment
import org.multipaz.asn1.ASN1Integer
import org.multipaz.compose.prompt.PromptDialogs
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
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.models.digitalcredentials.DigitalCredentials
import org.multipaz.models.presentment.PresentmentModel
import org.multipaz.models.presentment.PresentmentSource
import org.multipaz.models.presentment.SimplePresentmentSource
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustPoint
import org.multipaz.util.Logger
import org.multipaz.util.Platform
import org.multipaz.util.fromHex
import kotlin.time.Duration.Companion.days

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
                val now = Clock.System.now()
                val signedAt = now
                val validFrom = now
                val validUntil = now + 365.days
                val iacaKey = Crypto.createEcPrivateKey(EcCurve.P256)
                val iacaCert = MdocUtil.generateIacaCertificate(
                    iacaKey = iacaKey,
                    subject = X500Name.fromName(name = "CN=Test IACA Key"),
                    serial = ASN1Integer.fromRandom(numBits = 128),
                    validFrom = validFrom,
                    validUntil = validUntil,
                    issuerAltNameUrl = "https://issuer.example.com",
                    crlUrl = "https://issuer.example.com/crl"
                )
                val dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
                val dsCert = MdocUtil.generateDsCertificate(
                    iacaCert = iacaCert,
                    iacaKey = iacaKey,
                    dsKey = dsKey.publicKey,
                    subject = X500Name.fromName(name = "CN=Test DS Key"),
                    serial = ASN1Integer.fromRandom(numBits = 128),
                    validFrom = validFrom,
                    validUntil = validUntil
                )
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
                val mdocCredential =
                    DrivingLicense.getDocumentType().createMdocCredentialWithSampleData(
                        document = document,
                        secureArea = secureArea,
                        createKeySettings = CreateKeySettings(
                            algorithm = Algorithm.ESP256,
                            nonce = "Challenge".encodeToByteString(),
                            userAuthenticationRequired = true
                        ),
                        dsKey = dsKey,
                        dsCertChain = X509CertChain(listOf(dsCert)),
                        signedAt = signedAt,
                        validFrom = validFrom,
                        validUntil = validUntil,
                    )
            }else{
                Logger.i(appName,"document already exists")
            }
            presentmentModel = PresentmentModel().apply { setPromptModel(promptModel) }
            readerTrustManager = TrustManager().apply {
                addTrustPoint(
                    TrustPoint(
                        certificate = X509Cert.fromPem(
                            """
                                -----BEGIN CERTIFICATE-----
                                MIICUTCCAdegAwIBAgIQppKZHI1iPN290JKEA79OpzAKBggqhkjOPQQDAzArMSkwJwYDVQQDDCBP
                                V0YgTXVsdGlwYXogVGVzdEFwcCBSZWFkZXIgUm9vdDAeFw0yNDEyMDEwMDAwMDBaFw0zNDEyMDEw
                                MDAwMDBaMCsxKTAnBgNVBAMMIE9XRiBNdWx0aXBheiBUZXN0QXBwIFJlYWRlciBSb290MHYwEAYH
                                KoZIzj0CAQYFK4EEACIDYgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+wih+L79b7jyqUl99sbeU
                                npxaLD+cmB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH5RulaSWThWBfMyRjsfVODkosHLCDnbPV
                                o4G/MIG8MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMFYGA1UdHwRPME0wS6BJ
                                oEeGRWh0dHBzOi8vZ2l0aHViLmNvbS9vcGVud2FsbGV0LWZvdW5kYXRpb24tbGFicy9pZGVudGl0
                                eS1jcmVkZW50aWFsL2NybDAdBgNVHQ4EFgQUq2Ub4FbCkFPx3X9s5Ie+aN5gyfUwHwYDVR0jBBgw
                                FoAUq2Ub4FbCkFPx3X9s5Ie+aN5gyfUwCgYIKoZIzj0EAwMDaAAwZQIxANN9WUvI1xtZQmAKS4/D
                                ZVwofqLNRZL/co94Owi1XH5LgyiBpS3E8xSxE9SDNlVVhgIwKtXNBEBHNA7FKeAxKAzu4+MUf4gz
                                8jvyFaE0EUVlS2F5tARYQkU6udFePucVdloi
                                -----END CERTIFICATE-----
                            """.trimIndent().trim()
                        ),
                        displayName = "OWF Multipaz TestApp",
                        displayIcon = null,
                        privacyPolicyUrl = "https://apps.multipaz.org"
                    )
                )
                addTrustPoint(
                    TrustPoint(
                        certificate = X509Cert(
                            "30820269308201efa0030201020210b7352f14308a2d40564006785270b0e7300a06082a8648ce3d0403033037310b300906035504060c0255533128302606035504030c1f76657269666965722e6d756c746970617a2e6f726720526561646572204341301e170d3235303631393232313633325a170d3330303631393232313633325a3037310b300906035504060c0255533128302606035504030c1f76657269666965722e6d756c746970617a2e6f7267205265616465722043413076301006072a8648ce3d020106052b81040022036200046baa02cc2f2b7c77f054e9907fcdd6c87110144f07acb2be371b2e7c90eb48580c5e3851bcfb777c88e533244069ff78636e54c7db5783edbc133cc1ff11bbabc3ff150f67392264c38710255743fee7cde7df6e55d7e9d5445d1bde559dcba8a381bf3081bc300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff02010030560603551d1f044f304d304ba049a047864568747470733a2f2f6769746875622e636f6d2f6f70656e77616c6c65742d666f756e646174696f6e2d6c6162732f6964656e746974792d63726564656e7469616c2f63726c301d0603551d0e04160414b18439852f4a6eeabfea62adbc51d081f7488729301f0603551d23041830168014b18439852f4a6eeabfea62adbc51d081f7488729300a06082a8648ce3d040303036800306502302a1f3bb0afdc31bcee73d3c5bf289245e76bd91a0fd1fb852b45fc75d3a98ba84430e6a91cbfc6b3f401c91382a43a64023100db22d2243644bb5188f2e0a102c0c167024fb6fe4a1d48ead55a6893af52367fb3cdbd66369aa689ecbeb5c84f063666".fromHex()
                        ),
                        displayName = "Multipaz Verifier",
                        displayIcon = null,
                        privacyPolicyUrl = "https://apps.multipaz.org"
                    )
                )
            }
            presentmentSource = SimplePresentmentSource(
                documentStore = documentStore,
                documentTypeRepository = documentTypeRepository,
                readerTrustManager = readerTrustManager,
                preferSignatureToKeyAgreement = true,
                domainMdocSignature = "mdoc",
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
        MaterialTheme {
            Column(
                modifier = Modifier.fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                PromptDialogs(promptModel)
                Spacer(modifier = Modifier.height(30.dp))
                MembershipCard()
            }

        }
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