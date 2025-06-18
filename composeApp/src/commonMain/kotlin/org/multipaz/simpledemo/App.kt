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

import org.jetbrains.compose.ui.tooling.preview.Preview
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.util.Platform.getNonBackedUpStorage
import org.multipaz.util.Platform.getSecureArea
import simplemultipazdemo.composeapp.generated.resources.Res
import simplemultipazdemo.composeapp.generated.resources.amc // Your drawable resource item


lateinit var storage: Storage
lateinit var secureArea: SecureArea
lateinit var secureAreaRepository: SecureAreaRepository

lateinit var documentTypeRepository: DocumentTypeRepository
lateinit var documentStore: DocumentStore
//
private val documents = mutableStateListOf<Document>()




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
                     secureArea = getSecureArea(org.multipaz.simpledemo.storage)
                     secureAreaRepository = SecureAreaRepository.Builder().add(secureArea).build()

                     documentStore = buildDocumentStore(
                        storage = storage, secureAreaRepository = secureAreaRepository
                    ) {}

                    //TODO(), in the future will store cardArt , so far didn't  find good solution to find convert Res.drawble.img to ByteString
                    createStorage(
                        displayName = "Tom Lee's AMC Membership",
//                        cardArt = amcImageBytes,
                        others = amc_card_number.encodeToByteString()
                    )
                }
            }
        }
    }
}