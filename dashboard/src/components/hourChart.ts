import {
  Chart,
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
} from 'chart.js';
import { rows } from '../state.js';

Chart.register(BarController, BarElement, CategoryScale, LinearScale, Tooltip);

let _chart: Chart | null = null;

export function renderHourChart(): void {
  const canvas = document.getElementById('hour-canvas') as HTMLCanvasElement | null;
  if (!canvas) return;

  const scoped = rows();
  const counts = new Array(24).fill(0);
  for (const e of scoped) counts[e.hour]++;

  const labels = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'));

  if (_chart) {
    _chart.destroy();
    _chart = null;
  }

  const ctx = canvas.getContext('2d')!;

  _chart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ data: counts, backgroundColor: '#A822BF', borderRadius: 2 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#a99fc0', font: { size: 10 } }, grid: { color: '#3a2a52' } },
        y: { ticks: { color: '#a99fc0' }, grid: { color: '#3a2a52' } },
      },
    },
  });
}
