use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use walkdir::WalkDir;

use selinux_cascade::compile_combined;

pub fn full_system(c: &mut Criterion) {
    let full_system_path = "data/policies/full_system";
    let mut policy_files = Vec::new();

    for entry in WalkDir::new(full_system_path) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() && entry.path().extension().unwrap_or_default() == "cas" {
            policy_files.push(entry.path().display().to_string());
        }
    }

    let policy_files: Vec<&str> = policy_files.iter().map(|s| s as &str).collect();

    c.bench_function("Full system compile", |b| {
        b.iter_batched(
            || policy_files.clone(),
            |policy_files| compile_combined(black_box(policy_files)),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, full_system);
criterion_main!(benches);
