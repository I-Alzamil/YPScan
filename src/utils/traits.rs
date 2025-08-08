use crate::utils::bags::ResultBag;

pub trait Module {
    fn prepare(&mut self);

    fn run(&mut self, queue: std::sync::Arc<crate::utils::queue::QueueManager>);
}

pub trait Component<T: ?Sized>: Sync + Send {
    fn prepare(&mut self);
    
    fn scan(
        &self,
        target: &T,
        bag: &mut ResultBag
    ) -> Result<(),()>;
}