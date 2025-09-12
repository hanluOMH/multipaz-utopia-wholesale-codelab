package org.multipaz.samples.wallet.cmp


import androidx.compose.runtime.Composable
import coil3.ImageLoader
import coil3.network.ktor2.KtorNetworkFetcherFactory

import io.ktor.client.HttpClient
import org.multipaz.compose.digitalcredentials.CredentialManagerPresentmentActivity
import org.multipaz.samples.wallet.cmp.ui.AppTheme
import org.multipaz.util.Platform

class CredmanActivity: CredentialManagerPresentmentActivity() {
    override suspend fun getSettings(): Settings {
        val app = App.Companion.getInstance()
        app.init()
        val imageLoader = ImageLoader.Builder(applicationContext).components {
            add(KtorNetworkFetcherFactory(HttpClient(platformHttpClientEngineFactory().create())))
        }.build()

        val stream = assets.open("privilegedUserAgents.json")
        val data = ByteArray(stream.available())
        stream.read(data)
        stream.close()
        val privilegedAllowList = data.decodeToString()

        return Settings(
            appName = platformAppName,
            appIcon = platformAppIcon,
            promptModel = Platform.promptModel,
            applicationTheme = @Composable { AppTheme(it) },
            documentTypeRepository = app.documentTypeRepository,
            presentmentSource = app.presentmentSource,
            imageLoader = imageLoader,
            privilegedAllowList = privilegedAllowList,
        )
    }
}
