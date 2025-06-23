package org.multipaz.simpledemo

import MembershipCard
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
// import io.ktor.client.request.forms.formData
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.ByteString

import kotlinx.io.bytestring.encodeToByteString
import org.jetbrains.compose.resources.getDrawableResourceBytes
import org.jetbrains.compose.resources.getSystemResourceEnvironment

import org.jetbrains.compose.ui.tooling.preview.Preview
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.util.Logger
import org.multipaz.util.Platform.getNonBackedUpStorage
import org.multipaz.util.Platform.getSecureArea
import simplemultipazdemo.composeapp.generated.resources.Res
import simplemultipazdemo.composeapp.generated.resources.profile

lateinit var storage: Storage
lateinit var secureArea: SecureArea
lateinit var secureAreaRepository: SecureAreaRepository

lateinit var documentStore: DocumentStore
//
private val documents = mutableStateListOf<Document>()


private const val TAG = "APP"

@Composable
@Preview
fun App() {
    MaterialTheme {
        Scaffold { innerPadding ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(innerPadding)
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                val coroutineScope = rememberCoroutineScope()
                MembershipCard()
                coroutineScope.launch {
                     storage  = getNonBackedUpStorage()
                     secureArea = getSecureArea(storage)
                     secureAreaRepository = SecureAreaRepository.Builder().add(secureArea).build()

                     documentStore = buildDocumentStore(
                        storage = storage, secureAreaRepository = secureAreaRepository
                    ) {}

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


                    documents.add(document)
                    for (documentId in documentStore.listDocuments()) {
                        documentStore.lookupDocument(documentId)?.let { document ->
                            Logger.i(TAG,"document identifier : ${document.identifier}")
                        }
                    }

//                    for (documentId in documentStore.listDocuments()) {
//                        Logger.i(TAG,"delete ${document.identifier}")
//                        documentStore.deleteDocument(documentId)

//                    }
                    val credential = createCredential(document)

                    Logger.i(TAG,"credential identifier: ${credential.identifier}")



                }
            }
        }
    }
}



