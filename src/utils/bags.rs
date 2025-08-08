pub struct ResultBag {
    pub reasons: u32,
    pub info: Vec<(String,String)>,
    pub result: Vec<(String,String)>
}

impl Default for ResultBag {
    fn default() -> ResultBag {
        ResultBag {
            reasons: 0,
            info: Vec::new(),
            result: Vec::new()
        }
    }
}