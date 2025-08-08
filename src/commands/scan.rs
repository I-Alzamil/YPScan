pub fn initialize_scan() {
    // Create vec holding all components
    let mut modules: Vec<Box<dyn crate::utils::traits::Module>> = Vec::new();

    // Load default modules
    modules.push(Box::new(crate::modules::filescan::implementation::FScanner::default()));

    for module in modules.iter_mut() {
        // Prepare the module
        module.prepare();

        // Prepare queue manager
        let queue: std::sync::Arc<crate::utils::queue::QueueManager> = std::sync::Arc::new(crate::utils::queue::QueueManager::default());

        // Run the module
        module.run(queue);
    }
}