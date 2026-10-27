use std::{env,fs,process::Command,thread,time::Duration};
fn main(){
    let args=env::args().collect::<Vec<_>>();let marker=std::path::Path::new(&args[1]);
    fs::write(marker,std::process::id().to_string()).unwrap();
    if args.get(2).is_some_and(|a|a=="parent") {
        let child=Command::new(env::current_exe().unwrap()).arg(marker.with_extension("child")).arg("child").spawn().unwrap();
        fs::write(marker.with_extension("pid"),child.id().to_string()).unwrap();
    }
    thread::sleep(Duration::from_secs(20));
}
