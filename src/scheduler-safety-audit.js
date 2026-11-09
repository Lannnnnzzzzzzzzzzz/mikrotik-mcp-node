const MAX_RECORDS = 5000;
const MAX_TEXT_LENGTH = 16_384;
const MAX_FINDINGS = 500;
const MAX_UNKNOWN = 500;
const SECTION_KEYS = ['scheduler', 'scripts'];
const ALLOWED_STATUSES = new Set(['available', 'unavailable-or-not-permitted', 'error']);
const LIMITATION = 'Static advisory analysis of supplied RouterOS data only; no commands are executed and absence of a finding is not proof of safety.';

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function safeRead(object, key) {
  try {
    return object?.[key];
  } catch {
    return undefined;
  }
}

function normalizeStatus(section) {
  const value = isRecord(section) ? safeRead(section, 'status') : undefined;
  return ALLOWED_STATUSES.has(value) ? value : 'error';
}

function normalizeScheduleValue(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return null;
  return value.trim();
}

function parseBoolean(value) {
  if (value === true || value === false) return value;
  if (typeof value !== 'string') return undefined;
  switch (value.trim().toLowerCase()) {
    case 'true':
    case 'yes':
    case '1':
      return true;
    case 'false':
    case 'no':
    case '0':
      return false;
    default:
      return undefined;
  }
}

function isSupportedInterval(value) {
  if (!value) return false;
  // RouterOS duration forms commonly include `1d 00:00:00` and `00:05:00`.
  return /^(?:(?:\d+)(?:w|d|h|m|s)(?:\s+\d{1,2}:\d{2}:\d{2})?|\d{1,2}:\d{2}:\d{2})$/i.test(value);
}

function isSupportedStartTime(value) {
  if (value?.toLowerCase() === 'startup') return true;
  const match = /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(value ?? '');
  if (!match) return false;
  const [, hours, minutes, seconds] = match.map(Number);
  return hours <= 23 && minutes <= 59 && seconds <= 59;
}

function stripCommentsAndStrings(source) {
  return source
    .split(/\r?\n/)
    .map((line) => line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ' ').replace(/#.*$/, ' '))
    .join('\n');
}

function commandRiskCodes(source) {
  const code = stripCommentsAndStrings(source).toLowerCase();
  const risks = [];
  const patterns = [
    ['router-reboot', /\breboot\b/],
    ['router-shutdown', /\bshutdown\b/],
    ['configuration-reset', /\breset-configuration\b/],
    ['configuration-import', /\bimport\b/],
    ['configuration-remove', /\bremove\b/],
    ['remote-fetch', /\bfetch\b/],
    ['script-execution', /\bscript\s+run\b/],
  ];
  for (const [risk, pattern] of patterns) if (pattern.test(code)) risks.push(risk);
  return risks;
}

function sectionRows(section) {
  const records = safeRead(section, 'records');
  if (Array.isArray(records)) return records;
  const entries = safeRead(section, 'entries');
  return Array.isArray(entries) ? entries : null;
}

function inspectScheduler(row) {
  if (!isRecord(row)) return { unknown: 'unsupported-record' };
  const disabled = parseBoolean(safeRead(row, 'disabled'));
  if (disabled === true) return { riskCodes: [] };
  if (disabled !== false) return { unknown: 'unsupported-disabled-state' };
  const interval = normalizeScheduleValue(safeRead(row, 'interval'));
  const startTime = normalizeScheduleValue(safeRead(row, 'start-time'));
  const onEvent = safeRead(row, 'on-event');
  if (!startTime) return { unknown: 'unsupported-start-time' };
  if (!isSupportedStartTime(startTime)) return { unknown: 'unsupported-start-time' };
  if (interval && !isSupportedInterval(interval)) return { unknown: 'unsupported-interval' };
  if (onEvent === undefined || onEvent === null || onEvent === '') return { unknown: 'unsupported-on-event' };
  if (typeof onEvent !== 'string' || onEvent.length > MAX_TEXT_LENGTH) return { unknown: 'unsupported-on-event' };

  const riskCodes = commandRiskCodes(onEvent);
  if (!interval) riskCodes.push('one-shot-schedule');
  return { riskCodes };
}

function inspectScript(row) {
  if (!isRecord(row)) return { unknown: 'unsupported-record' };
  const source = safeRead(row, 'source');
  if (typeof source !== 'string' || source.length > MAX_TEXT_LENGTH || source.length === 0) {
    return { unknown: 'unsupported-source' };
  }
  return { riskCodes: commandRiskCodes(source) };
}

/** Analyze supplied RouterOS scheduler and script snapshots without executing or exposing their contents. */
export function buildSchedulerSafetyAudit(input = {}) {
  const rawSections = isRecord(input) ? safeRead(input, 'sections') : undefined;
  const sections = isRecord(rawSections) ? rawSections : {};
  const findings = [];
  const unknown = [];
  const riskCounts = {};
  let findingCount = 0;
  let unknownCount = 0;
  let analyzedCount = 0;
  const sectionSummaries = {};

  const addUnknown = (section, index, reason) => {
    unknownCount += 1;
    if (unknown.length < MAX_UNKNOWN) unknown.push({ section, ...(index === null ? {} : { index }), reason });
  };

  for (const sectionKey of SECTION_KEYS) {
    const section = safeRead(sections, sectionKey);
    let status = normalizeStatus(section);
    const hasSection = Object.prototype.hasOwnProperty.call(sections, sectionKey);
    const rows = status === 'available' && isRecord(section) ? sectionRows(section) : null;
    let reason = null;

    if (!hasSection) {
      status = 'error';
      reason = 'missing-section';
    } else if (status !== 'available') {
      reason = 'section-unavailable';
    } else if (!rows) {
      status = 'error';
      reason = 'unsupported-records';
    } else if (safeRead(section, 'partial') === true || safeRead(section, 'truncated') === true) {
      reason = 'partial-section';
    } else {
      const total = safeRead(section, 'total');
      const normalizedTotal = total === undefined ? rows.length
        : (typeof total === 'number' ? total : (typeof total === 'string' && /^\d+$/.test(total) ? Number(total) : NaN));
      if (!Number.isSafeInteger(normalizedTotal) || normalizedTotal !== rows.length) reason = 'partial-section';
      else if (rows.length > MAX_RECORDS) reason = 'record-limit-exceeded';
    }

    sectionSummaries[sectionKey] = {
      status,
      recordCount: rows ? rows.length : null,
      completeness: reason ? 'unknown' : 'complete',
    };

    if (reason) {
      addUnknown(sectionKey, null, reason);
      continue;
    }

    for (let index = 0; index < rows.length; index += 1) {
      const result = sectionKey === 'scheduler' ? inspectScheduler(rows[index]) : inspectScript(rows[index]);
      if (result.unknown) {
        addUnknown(sectionKey, index, result.unknown);
        continue;
      }
      analyzedCount += 1;
      if (result.riskCodes.length === 0) continue;
      const uniqueRiskCodes = [...new Set(result.riskCodes)];
      for (const riskCode of uniqueRiskCodes) riskCounts[riskCode] = (riskCounts[riskCode] ?? 0) + 1;
      findingCount += 1;
      if (findings.length < MAX_FINDINGS) findings.push({ section: sectionKey, index, riskCodes: uniqueRiskCodes });
    }
  }

  return {
    coverage: { sections: sectionSummaries },
    findings,
    findingsCount: findingCount,
    findingsTruncated: findingCount > findings.length,
    unknown,
    unknownCount,
    unknownTruncated: unknownCount > unknown.length,
    counts: { analyzed: analyzedCount, findings: findingCount, unknown: unknownCount, riskCodes: riskCounts },
    notes: [
      'Only recognized interval, start-time, on-event, and source values are inspected; partial or unsupported sections are reported as unknown.',
      'Command indicators are heuristic and can produce false positives or miss indirect/dynamically generated behavior.',
      LIMITATION,
    ],
  };
}
