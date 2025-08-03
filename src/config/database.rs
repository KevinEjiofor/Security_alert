use sqlx::{PgPool, Pool, Postgres, migrate::Migrator};
use std::sync::Arc;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Database {
    pub pool: Arc<PgPool>,
}

impl Database {
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPool::connect(database_url).await?;

        let migrations_path = Path::new("migrations");
        let migrator = Migrator::new(migrations_path).await?;
        migrator.run(&pool).await?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub fn get_pool(&self) -> &Pool<Postgres> {
        &self.pool
    }
}