use dagger_sdk::HostDirectoryOpts;

fn command_name() -> String {
    std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ci-all".to_string())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let command = command_name();

    dagger_sdk::connect(move |client| {
        let command = command.clone();
        async move {
            let host_source = client.host().directory_opts(
                ".",
                HostDirectoryOpts {
                    exclude: Some(vec![
                        ".git",
                        "target",
                        "bindings/swift/.build",
                        "bindings/swift/.swiftpm",
                    ]),
                    include: None,
                    no_cache: None,
                    gitignore: Some(true),
                },
            );

            let rust = client
                .container()
                .from("rust:1.88")
                .with_mounted_directory("/src", host_source)
                .with_workdir("/src");

            match command.as_str() {
                "build-staticlib" => {
                    let output = rust
                        .with_exec(vec!["cargo", "rustc", "--lib", "--crate-type", "staticlib"])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "release-staticlib" => {
                    let output = rust
                        .with_exec(vec![
                            "cargo",
                            "rustc",
                            "--release",
                            "--lib",
                            "--crate-type",
                            "staticlib",
                        ])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "test-abi" => {
                    let output = rust
                        .with_exec(vec!["cargo", "test", "--test", "ffi_bindings"])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                "ci-all" => {
                    let output = rust
                        .with_exec(vec!["cargo", "rustc", "--lib", "--crate-type", "staticlib"])
                        .with_exec(vec![
                            "cargo",
                            "rustc",
                            "--release",
                            "--lib",
                            "--crate-type",
                            "staticlib",
                        ])
                        .with_exec(vec!["cargo", "test", "--test", "ffi_bindings"])
                        .stdout()
                        .await?;
                    println!("{output}");
                }
                other => {
                    return Err(eyre::eyre!(
                        "unknown command '{other}'. Supported: build-staticlib, release-staticlib, test-abi, ci-all"
                    ));
                }
            }

            Ok(())
        }
    })
    .await?;

    Ok(())
}