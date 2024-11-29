# BUILD IOS TARGETS
rustup toolchain install 1.64.0 --target aarch64-apple-ios  --profile minimal --no-self-update
cargo  build --release --target aarch64-apple-ios &
rustup toolchain install 1.64.0 --target aarch64-apple-ios-sim  --profile minimal --no-self-update
cargo  build --release --target aarch64-apple-ios-sim &
rustup toolchain install 1.64.0 --target x86_64-apple-ios  --profile minimal --no-self-update
cargo  build --release --target x86_64-apple-ios &

# BUILD ANDROID TARGETS

#cargo install --bins --git https://github.com/rust-embedded/cross --tag v0.2.4 cross
cargo install cross --git https://github.com/cross-rs/cross

rustup toolchain install 1.64.0 --target aarch64-linux-android --profile minimal --no-self-update
cross build --release --target aarch64-linux-android &
rustup toolchain install 1.64.0 --target armv7-linux-androideabi --profile minimal --no-self-update
cross build --release --target armv7-linux-androideabi &
rustup toolchain install 1.64.0 --target i686-linux-android --profile minimal --no-self-update
cross build --release --target i686-linux-android &
rustup toolchain install 1.64.0 --target x86_64-linux-android --profile minimal --no-self-update
cross build --release --target x86_64-linux-android &

# BUILD MAC OS TARGETS
../../build-universal.sh