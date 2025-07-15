use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::info;

pub struct ParallelFallibleWorkQueue<T> {
    join_set: JoinSet<eyre::Result<T>>,
    rate_limit: Arc<Semaphore>,
    description: String,
}
impl<T> ParallelFallibleWorkQueue<T>
where
    T: Send + 'static,
{
    pub fn new(description: impl Into<String>, rate_limit: usize) -> Self {
        let description = description.into();
        ParallelFallibleWorkQueue {
            join_set: JoinSet::new(),
            rate_limit: Arc::new(Semaphore::new(rate_limit)),
            description,
        }
    }

    pub fn enqueue(
        &mut self,
        task: impl Future<Output = eyre::Result<T>> + Send + 'static,
    ) -> &mut Self
    where
        T: Send + 'static,
    {
        let rate_limt = self.rate_limit.clone();
        self.join_set.spawn(async move {
            let permit = rate_limt.acquire().await;
            let rtn = task.await?;
            drop(permit);
            Ok(rtn)
        });
        self
    }
    pub async fn join(mut self) -> eyre::Result<Vec<T>> {
        let mut rtn = Vec::new();
        while let Some(x) = self.join_set.join_next().await {
            info!("{}, {} tasks remain", self.description, self.join_set.len());
            rtn.push(x??);
        }
        Ok(rtn)
    }
}
