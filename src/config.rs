enum Mode {
    Client,
    Server,
}

pub struct Config {
    mode: Mode,
}

impl Config {
    pub fn new() -> Self {
        Self { mode: Mode::Client }
    }
}
