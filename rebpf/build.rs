fn main() {
    for src in run("find -maxdepth 1").split("\n") {
        if src.ends_with(".c") || src.ends_with(".h") || src.ends_with(".sh") {
            println!("cargo:rerun-if-changed={src}");
        }
    }

    let bindings_rs = run("bindgen bpf-shared.h --rustified-enum .* -- -DBPF -DBINDGEN");
    std::fs::write("bindings.rs", bindings_rs).unwrap();

    let bpf_trace = if cfg!(feature = "bpf-trace") {
        "BPF_TRACE=1"
    } else {
        ""
    };

    let out_dir = std::env::var("OUT_DIR").unwrap();
    run(format!(
        "env {bpf_trace} NO_COMPILE_COMMANDS=1 REBPF_SRC=. bash ./build-loader.sh"
    ));

    println!("cargo:rustc-link-arg={out_dir}/bpf-load.o");
    for lib in run("pkg-config --libs libbpf libcap").split(" ") {
        println!("cargo:rustc-link-arg={lib}");
    }
}

fn run(cmd: impl AsRef<str>) -> String {
    let cmd = cmd.as_ref();
    let (prog, args) = cmd.split_once(" ").unwrap();
    let res = std::process::Command::new(prog)
        .args(args.split(" ").filter(|a| !a.is_empty()))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|e| e.wait_with_output());
    if let Err(err) = res {
        panic!("Can't execute {prog:?}: {err}");
    }
    let res = res.unwrap();
    if !res.status.success() {
        panic!("Command {cmd:?} exited with error");
    }
    String::from_utf8(res.stdout).unwrap().trim().to_string()
}
