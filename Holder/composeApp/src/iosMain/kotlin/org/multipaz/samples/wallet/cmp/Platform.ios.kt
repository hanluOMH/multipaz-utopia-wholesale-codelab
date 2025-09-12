package org.multipaz.samples.wallet.cmp

import io.ktor.client.engine.HttpClientEngineFactory
import io.ktor.client.engine.darwin.Darwin
import org.multipaz.prompt.IosPromptModel
import org.multipaz.prompt.PromptModel
import platform.UIKit.UIDevice
import utopiasample.composeapp.generated.resources.Res
import utopiasample.composeapp.generated.resources.app_icon

class IOSPlatform: Platform {
    override val name: String = UIDevice.currentDevice.systemName() + " " + UIDevice.currentDevice.systemVersion
}

actual fun getPlatform(): Platform = IOSPlatform()
actual val platformAppName = "UtopiaSample"

actual fun platformHttpClientEngineFactory(): HttpClientEngineFactory<*> = Darwin

actual val platformAppIcon = Res.drawable.app_icon
