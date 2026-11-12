//! Shared fixtures for SDK integration tests: the self-owned Java probe.

#![allow(dead_code)]

use nacl_next_sdk::context::SdkContext;
use nacl_next_sdk::instance::{
    CreateInstanceRequest, InstallationInfo, InstallationState, InstanceDefaults,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const PROBE_SOURCE: &str = r#"
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class NaclNextProbe {
    public static void main(String[] args) throws Exception {
        StringBuilder arguments = new StringBuilder();
        for (String value : args) {
            arguments.append(value).append('\n');
        }
        Path workingDirectory = Paths.get("");
        Path argumentsFile = workingDirectory.resolve("probe-args.txt");
        Files.write(argumentsFile, arguments.toString().getBytes("UTF-8"));
        Files.write(
            workingDirectory.resolve("probe-cwd.txt"),
            workingDirectory.toAbsolutePath().toString().getBytes("UTF-8"));
        for (String value : args) {
            if (value.equals("--fail")) {
                System.exit(7);
            }
        }
        System.exit(0);
    }
}
"#;

pub struct Fixture {
    pub _root: tempfile::TempDir,
    pub context: SdkContext,
    pub java_executable: PathBuf,
}

fn unique_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nacl-next-sdk-s1-{}-{}-{nanos}",
        label,
        std::process::id()
    ))
}

pub fn require_javac() {
    let status = Command::new("javac").arg("-version").output();
    match status {
        Ok(output) if output.status.success() => {}
        other => panic!(
            "本机没有可用的 javac，无法执行自有 Java 小程序验证：{other:?}。\
             这是环境缺口，按指南如实记为待验证，不用桩程序冒充。"
        ),
    }
}

pub fn build_probe_fixture(label: &str) -> Fixture {
    require_javac();
    let root = tempfile::tempdir_in(unique_root(label).parent().unwrap()).expect("temp root");
    let context = SdkContext::from_root(root.path());
    context.initialize().expect("context should initialize");

    let java = nacl_next_sdk::java::detect_java_runtimes(&context)
        .into_iter()
        .next()
        .expect("detect_java_runtimes should find at least one Java (JDK present for javac)");
    let java_executable = PathBuf::from(&java.path);
    let major = java
        .major_version
        .expect("detected Java should report a major version");

    let source_dir = root.path().join("probe-src");
    let classes_dir = root.path().join("probe-classes");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::create_dir_all(&classes_dir).unwrap();
    std::fs::write(source_dir.join("NaclNextProbe.java"), PROBE_SOURCE).unwrap();
    let compile = Command::new("javac")
        .arg("-encoding")
        .arg("UTF-8")
        .arg(source_dir.join("NaclNextProbe.java"))
        .arg("-d")
        .arg(&classes_dir)
        .output()
        .expect("javac should start");
    assert!(
        compile.status.success(),
        "javac 编译探针失败：{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let client_jar = context.versions_root.join("1.21.1-probe.jar");
    let package = Command::new("jar")
        .arg("--create")
        .arg("--file")
        .arg(&client_jar)
        .arg("-C")
        .arg(&classes_dir)
        .arg(".")
        .output()
        .expect("jar should start");
    assert!(
        package.status.success(),
        "jar 打包探针失败：{}",
        String::from_utf8_lossy(&package.stderr)
    );

    let metadata = serde_json::json!({
        "mainClass": "NaclNextProbe",
        "type": "release",
        "assetIndex": {"id": "1"},
        "javaVersion": {"majorVersion": major},
        "libraries": [],
        "arguments": {
            "game": [
                "--username", "${auth_player_name}",
                "--uuid", "${auth_uuid}",
                "--userType", "${user_type}"
            ],
            "jvm": []
        }
    });
    std::fs::write(
        context.versions_root.join("1.21.1-probe.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();

    Fixture {
        _root: root,
        context,
        java_executable,
    }
}

pub fn ready_instance(
    context: &SdkContext,
    java_executable: &Path,
) -> nacl_next_sdk::instance::InstanceConfig {
    let mut instance = nacl_next_sdk::instance::create_instance(
        context,
        CreateInstanceRequest {
            name: "Java 探针实例".to_string(),
            game_version: "1.21.1-probe".to_string(),
        },
        &InstanceDefaults::default(),
    )
    .expect("instance should be created");
    instance.installation = InstallationInfo {
        state: InstallationState::Ready,
        installed_epoch_ms: None,
    };
    instance.java = nacl_next_sdk::instance::JavaSelection::Custom {
        path: java_executable.to_path_buf(),
    };
    nacl_next_sdk::instance::update_instance(context, instance)
        .expect("instance should become ready")
}

pub mod http_server;
