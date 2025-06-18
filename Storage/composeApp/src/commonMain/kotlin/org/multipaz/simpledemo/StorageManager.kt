package org.multipaz.simpledemo

import kotlinx.io.bytestring.ByteString
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.util.Platform.getNonBackedUpStorage
import org.multipaz.util.Platform.getSecureArea


suspend fun createStorage(displayName: String,  others: ByteString){


    val document = documentStore.createDocument(
        displayName = displayName,
        typeDisplayName = "Membership Card",
        cardArt = null,
        issuerLogo = null,
        other = others,
    )


}