package org.multipaz.samples.wallet.cmp

import io.ktor.client.engine.HttpClientEngineFactory
import org.jetbrains.compose.resources.DrawableResource
import org.multipaz.prompt.PromptModel

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform

expect fun platformHttpClientEngineFactory(): HttpClientEngineFactory<*>

expect val platformAppName: String

expect val platformAppIcon: DrawableResource

