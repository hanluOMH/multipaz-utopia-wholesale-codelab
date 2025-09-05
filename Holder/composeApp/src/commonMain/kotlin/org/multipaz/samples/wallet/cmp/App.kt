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
import coil3.ImageLoader
import coil3.compose.LocalPlatformContext
import io.ktor.utils.io.printStack
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import utopiasample.composeapp.generated.resources.Res
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
import org.multipaz.util.toBase64Url
import kotlin.time.Duration.Companion.days
import utopiasample.composeapp.generated.resources.profile
import org.jetbrains.compose.resources.getDrawableResourceBytes
import org.jetbrains.compose.resources.getSystemResourceEnvironment
import org.multipaz.samples.wallet.cmp.UtopiaMemberInfo
import org.multipaz.compose.permissions.rememberBluetoothEnabledState
import org.multipaz.compose.presentment.MdocProximityQrPresentment
import org.multipaz.compose.presentment.MdocProximityQrSettings
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.trustmanagement.TrustManagerLocal
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustPointAlreadyExistsException
import org.multipaz.util.Logger
import kotlin.time.Clock.System.now
import kotlin.time.ExperimentalTime

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
                val now = now()
                val signedAt = now
                val validFrom = now
                val validUntil = now + 365.days
                val iacaCert = X509Cert.fromPem(
                    Res.readBytes("files/iaca_certificate.pem").decodeToString().trimIndent().trim()
                )
                Logger.i(appName, iacaCert.toPem())
                val iacaKey = EcPrivateKey.fromPem(
                    Res.readBytes("files/iaca_private_key.pem").decodeToString().trimIndent().trim(),
                    iacaCert.ecPublicKey
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

            val readerTrustManager = TrustManagerLocal(storage = storage, identifier = "reader")
            try {
                readerTrustManager.apply{
                    addX509Cert(
                        certificate = X509Cert.fromPem(
                            Res.readBytes("files/test_app_reader_root_certificate.pem").decodeToString().trimIndent().trim()
                        ),
                        metadata = TrustMetadata(
                            displayName = "OWF Multipaz Test App Reader",
                            displayIcon = null,
                            privacyPolicyUrl = "https://apps.multipaz.org"
                        )
                    )
                    addX509Cert(
                        certificate = X509Cert.fromPem(
                            Res.readBytes("files/reader_root_certificate.pem").decodeToString().trimIndent().trim(),
                        ),
                        metadata = TrustMetadata(
                            displayName = "Multipaz Identity Reader (Trusted Devices)",
                            displayIcon = null,
                            privacyPolicyUrl = "https://apps.multipaz.org"
                        )
                    )
                    addX509Cert(
                        certificate = X509Cert.fromPem(
                            Res.readBytes("files/reader_root_certificate_for_untrust_device.pem").decodeToString().trimIndent().trim(),
                        ),
                        metadata = TrustMetadata(
                            displayName = "Multipaz Identity Reader (UnTrusted Devices)",
                            displayIcon = null,
                            privacyPolicyUrl = "https://apps.multipaz.org"
                        )
                    )
                }
            } catch (e: TrustPointAlreadyExistsException) {
                e.printStackTrace()
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
        val bleEnabledState = rememberBluetoothEnabledState()
        val context = LocalPlatformContext.current
        val imageLoader = remember { ImageLoader.Builder(context).components { /* network loader omitted */ }.build() }
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
        }else if (!bleEnabledState.isEnabled) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Button(onClick = { coroutineScope.launch { bleEnabledState.enable() } }) {
                    Text("Enable BLE")
                }
            }
        } else {
            MdocProximityQrPresentment(
                appName = appName,
                appIconPainter = painterResource(appIcon),
                presentmentModel = presentmentModel,
                presentmentSource = presentmentSource,
                promptModel = promptModel,
                documentTypeRepository = documentTypeRepository,
                imageLoader = imageLoader,
                allowMultipleRequests = false,
                showQrButton = { onQrButtonClicked -> showQrButton(onQrButtonClicked) },
                showQrCode = { uri -> showQrCode(uri) }
            )

        }
    }

    @Composable
    private fun showQrButton(
        onQrButtonClicked: (settings: MdocProximityQrSettings) -> Unit
    ) {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(onClick = {
                val connectionMethods = listOf(
                    MdocConnectionMethodBle(
                        supportsPeripheralServerMode = false,
                        supportsCentralClientMode = true,
                        peripheralServerModeUuid = null,
                        centralClientModeUuid = UUID.randomUUID(),
                    )
                )
                onQrButtonClicked(
                    MdocProximityQrSettings(
                        availableConnectionMethods = connectionMethods,
                        createTransportOptions = MdocTransportOptions(bleUseL2CAP = true)
                    )
                )
            }) {
                Text("Present mDL via QR")
            }
        }
    }

    @Composable
    private fun showQrCode(uri: String) {
            Column(
                modifier = Modifier.fillMaxSize().padding(16.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                val qrCodeBitmap = remember { generateQrCode(uri) }
                Spacer(modifier = Modifier.height(130.dp))
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