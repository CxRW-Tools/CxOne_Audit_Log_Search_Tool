export const CAT_COLORS: Record<string, string> = {
  'Scanning': '#6B34FD',
  'Identity & Auth': '#006BD5',
  'Project Mgmt': '#A822BF',
  'Access Control': '#F25929',
  'Data Access': '#D91A3C',
  'Config': '#E89000',
  'Other': '#a99fc0',
};

export function truncate(s: string, maxLen: number): string {
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s;
}

export function allDaysInRange(dateMin: string, dateMax: string): string[] {
  const days: string[] = [];
  const start = new Date(dateMin + 'T00:00:00Z');
  const end = new Date(dateMax + 'T00:00:00Z');
  for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
    days.push(d.toISOString().slice(0, 10));
  }
  return days;
}
