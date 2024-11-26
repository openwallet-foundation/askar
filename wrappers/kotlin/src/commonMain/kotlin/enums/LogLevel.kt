package askar.enums

enum class LogLevel (val logLevel: Int) {
    RUST_LOG(-1),
    Off(0),
    Error(1),
    Warn(2),
    Info(3),
    Debug(4),
    Trace(5)
}