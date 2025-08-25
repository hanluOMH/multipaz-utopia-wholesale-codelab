package org.multipaz.samples.wallet.cmp

import utopiasample.composeapp.generated.resources.Res

suspend fun getIacaCert(): String = Res.readBytes("files/iaca_certificate.pem").decodeToString()

suspend fun getIacaPrivateKey(): String = Res.readBytes("files/iaca_private_key.pem").decodeToString()

suspend fun getTestAppReaderRootCert(): String = Res.readBytes("files/test_app_reader_root_certificate.pem").decodeToString()

suspend fun getReaderRootCert(): String = Res.readBytes("files/reader_root_certificate.pem").decodeToString()

suspend fun getReaderRootCertForUntrustDevice(): String = Res.readBytes("files/reader_root_certificate_for_untrust_device.pem").decodeToString()
