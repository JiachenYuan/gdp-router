use std::fs;
use capsule::{config::RuntimeConfig, Runtime, PortQueue, batch::Pipeline};


fn main() {
    println!("Hello, world!");
    let path = "runtime_config.toml";
    let content = fs::read_to_string(path).unwrap();
    let config: RuntimeConfig = toml::from_str(&content).unwrap();
    
    let runtime: Runtime = Runtime::build(config).unwrap();

    runtime.add_pipeline_to_port("eth0", installer)

    
    

}

fn installer(port_queue: PortQueue) -> impl Pipeline {
    
}
