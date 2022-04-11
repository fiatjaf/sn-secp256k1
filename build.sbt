scalaVersion := "3.1.1"
enablePlugins(ScalaNativePlugin, BindgenPlugin)

import bindgen.interface.Binding
import java.nio.file.Paths

bindgenBindings := Seq(
  Binding(
    Paths.get("/usr/include/secp256k1.h").toFile(),
    "secp256k1",
    cImports = List("secp256k1.h")
  )
)
