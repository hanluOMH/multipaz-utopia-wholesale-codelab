package org.multipaz.samples.wallet.cmp

import android.os.Build
import io.ktor.client.engine.HttpClientEngineFactory
import io.ktor.client.engine.android.Android
import org.multipaz.context.applicationContext
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.PromptModel
import utopiasample.composeapp.generated.resources.Res
import utopiasample.composeapp.generated.resources.app_icon

class AndroidPlatform : Platform {
    override val name: String = "Android ${Build.VERSION.SDK_INT}"
}

actual fun getPlatform(): Platform = AndroidPlatform()

actual fun platformHttpClientEngineFactory(): HttpClientEngineFactory<*> = Android


actual val platformAppName = applicationContext.getString(R.string.app_name)

actual val platformAppIcon = Res.drawable.app_icon

