import { copyFileSync, appendFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { benchmarkRegressions } from './gates';
import ceilings from '../../../backend/internal/service/perf-budget.json';
import { baseArgument, repo, results, run, withBaseline } from './common';

const ref = baseArgument();
if (!ref) throw new Error('Pass --base <revision> for same-runner benchmark comparison');
const pattern = '^(BenchmarkListDirectory|BenchmarkSearchWalk)$';

await withBaseline(ref, async (base, sha) => {
	// The identical fixture exercises both implementations, including a master
	// revision from before these benchmarks existed.
	for (const name of [
		'file_bench_test.go',
		'search_bench_test.go',
		'perf_budget_test.go',
		'perf-budget.json'
	]) {
		copyFileSync(
			join(repo, 'backend/internal/service', name),
			join(base, 'backend/internal/service', name)
		);
	}
	const binaries = [join(results, 'backend-base.test'), join(results, 'backend-head.test')];
	for (const [index, root] of [base, repo].entries()) {
		run(['go', 'test', '-c', '-o', binaries[index], './internal/service'], join(root, 'backend'));
	}
	const files = [join(results, 'backend-base.txt'), join(results, 'backend-head.txt')];
	for (const file of files) writeFileSync(file, '');
	for (let sample = 0; sample < 10; sample++) {
		// Alternate the first variant to distribute warm-up and thermal noise.
		for (const index of sample % 2 ? [1, 0] : [0, 1]) {
			appendFileSync(
				files[index],
				run([
					binaries[index],
					'-test.run=^$',
					`-test.bench=${pattern}`,
					'-test.benchmem',
					'-test.benchtime=200ms',
					'-test.count=1'
				])
			);
		}
	}
	const texts = await Promise.all(files.map((file) => Bun.file(file).text()));
	for (const text of texts) {
		for (const name of [
			'ListDirectory/name',
			'ListDirectory/type',
			'ListDirectory/size',
			'ListDirectory/modTime',
			'SearchWalk'
		]) {
			if (!new RegExp(`^Benchmark${name}-2\\s`, 'm').test(text))
				throw new Error(`Missing required benchmark ${name}`);
		}
	}
	const report = run([
		process.env.BENCHSTAT ?? 'benchstat',
		`base=${files[0]}`,
		`head=${files[1]}`
	]);
	writeFileSync(join(results, 'benchstat.txt'), `Baseline: ${sha}\n\n${report}`);
	console.log(report);
	const violations = benchmarkRegressions(texts[0], texts[1], ceilings);
	writeFileSync(
		join(results, 'backend-gate.json'),
		JSON.stringify(
			{
				base: sha,
				head: run(['git', 'rev-parse', 'HEAD']).trim(),
				samplesPerRevision: 10,
				gomaxprocs: 2,
				violations
			},
			null,
			2
		)
	);
	if (violations.length) throw new Error(violations.join('\n'));
});
