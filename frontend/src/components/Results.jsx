'use client';

/**
 * Results Component
 * Displays scan results with vulnerability details, statistics, and filtering
 */

import React, { useState, useMemo } from 'react';
import { SEVERITY_LEVELS } from '../config';

/**
 * Severity badge component
 */
const SeverityBadge = ({ severity }) => {
  const config = SEVERITY_LEVELS[severity] || SEVERITY_LEVELS.INFO;
  
  return (
    <span
      style={{
        backgroundColor: config.bgColor,
        color: config.color,
        padding: '4px 12px',
        borderRadius: '9999px',
        fontSize: '12px',
        fontWeight: '600',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
      }}
    >
      {config.label}
    </span>
  );
};

/**
 * Statistics card component
 */
const StatCard = ({ label, value, color }) => (
  <div
    style={{
      backgroundColor: '#ffffff',
      border: '1px solid #e5e7eb',
      borderRadius: '8px',
      padding: '16px',
      textAlign: 'center',
      minWidth: '100px',
    }}
  >
    <div
      style={{
        fontSize: '28px',
        fontWeight: '700',
        color: color || '#1f2937',
        marginBottom: '4px',
      }}
    >
      {value}
    </div>
    <div
      style={{
        fontSize: '12px',
        color: '#6b7280',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
      }}
    >
      {label}
    </div>
  </div>
);

/**
 * Vulnerability card component
 */
const VulnerabilityCard = ({ vulnerability, isExpanded, onToggle }) => {
  const {
  rule_id,
  rule_name,
  description,
  severity,
  file_path,
  line_number,
  column_number,
  code_snippet,
  remediation,
  cwe_id,
  owasp_category,
} = vulnerability;


  return (
    <div
      style={{
        backgroundColor: '#ffffff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        marginBottom: '12px',
        overflow: 'hidden',
        transition: 'box-shadow 0.2s ease',
      }}
    >
      {/* Header */}
      <button
        onClick={onToggle}
        style={{
          width: '100%',
          padding: '16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          backgroundColor: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <SeverityBadge severity={severity} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: '600', color: '#1f2937', marginBottom: '4px' }}>
              {rule_id}
            </div>
            <div style={{ fontSize: '14px', color: '#6b7280' }}>
              {file}:{line}:{column}
            </div>
          </div>
        </div>
        <svg
          style={{
            width: '20px',
            height: '20px',
            color: '#9ca3af',
            transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s ease',
          }}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded content */}
      {isExpanded && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid #e5e7eb' }}>
          {/* Message */}
          <div style={{ marginTop: '16px' }}>
            <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', marginBottom: '8px', textTransform: 'uppercase' }}>
              Description
            </h4>
            <p style={{ color: '#374151', lineHeight: '1.5' }}>{message}</p>
          </div>

          {/* Code snippet */}
          {code_snippet && (
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', marginBottom: '8px', textTransform: 'uppercase' }}>
                Code Snippet
              </h4>
              <pre
                style={{
                  backgroundColor: '#1f2937',
                  color: '#f3f4f6',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                  overflow: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {code_snippet}
              </pre>
            </div>
          )}

          {/* Recommendation */}
          {recommendation && (
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', marginBottom: '8px', textTransform: 'uppercase' }}>
                Recommendation
              </h4>
              <p style={{ color: '#374151', lineHeight: '1.5' }}>{recommendation}</p>
            </div>
          )}

          {/* Reference IDs */}
          <div style={{ marginTop: '16px', display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
            {cwe_id && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>CWE: </span>
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cwe_id.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ fontSize: '12px', color: '#2563eb', textDecoration: 'none' }}
                >
                  {cwe_id}
                </a>
              </div>
            )}
            {owasp_category && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>OWASP: </span>
                <span style={{ fontSize: '12px', color: '#374151' }}>{owasp_category}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Filter button component
 */
const FilterButton = ({ label, isActive, onClick, count }) => (
  <button
    onClick={onClick}
    style={{
      padding: '8px 16px',
      borderRadius: '6px',
      border: isActive ? '2px solid #2563eb' : '1px solid #e5e7eb',
      backgroundColor: isActive ? '#eff6ff' : '#ffffff',
      color: isActive ? '#2563eb' : '#374151',
      fontWeight: '500',
      fontSize: '14px',
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      transition: 'all 0.2s ease',
    }}
  >
    {label}
    {count !== undefined && (
      <span
        style={{
          backgroundColor: isActive ? '#2563eb' : '#e5e7eb',
          color: isActive ? '#ffffff' : '#6b7280',
          padding: '2px 8px',
          borderRadius: '9999px',
          fontSize: '12px',
        }}
      >
        {count}
      </span>
    )}
  </button>
);

/**
 * Main Results component
 */
const Results = ({ results, onClear }) => {
  const [expandedIds, setExpandedIds] = useState(new Set());
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const vulnerabilities = results?.findings || [];
  const severitySummary = results?.severity_summary?.by_severity || {};


  // Calculate statistics
  const stats = useMemo(() => {
    const stats = useMemo(() => {
  return {
    total: results?.total_findings || vulnerabilities.length,
    critical: severitySummary.critical || 0,
    high: severitySummary.high || 0,
    medium: severitySummary.medium || 0,
    low: severitySummary.low || 0,
    info: severitySummary.info || 0,
  };
}, [results, vulnerabilities, severitySummary]);


    return results.vulnerabilities.reduce(
      (acc, vuln) => {
        acc.total++;
        const severity = vuln.severity?.toUpperCase() || 'INFO';
        if (acc[severity.toLowerCase()] !== undefined) {
          acc[severity.toLowerCase()]++;
        }
        return acc;
      },
      { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    );
  }, [results]);

  // Filter vulnerabilities
  const filteredVulnerabilities = useMemo(() => {
    if (!vulnerabilities.length) return [];


    return vulnerabilities.filter((vuln) => {
      // Severity filter
      if (activeFilter !== 'ALL' && vuln.severity?.toUpperCase() !== activeFilter) {
        return false;
      }

      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          vuln.rule_id?.toLowerCase().includes(query) ||
          vuln.message?.toLowerCase().includes(query) ||
          vuln.file?.toLowerCase().includes(query)
        );
      }

      return true;
    });
  }, [results, activeFilter, searchQuery]);

  // Toggle expanded state
  const toggleExpanded = (id) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Expand/collapse all
  const expandAll = () => {
    setExpandedIds(new Set(filteredVulnerabilities.map((_, i) => i)));
  };

  const collapseAll = () => {
    setExpandedIds(new Set());
  };

  if (!results) {
    return null;
  }

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', padding: '24px' }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '24px',
        }}
      >
        <h2 style={{ fontSize: '24px', fontWeight: '700', color: '#1f2937' }}>
          Scan Results
        </h2>
        <button
          onClick={onClear}
          style={{
            padding: '8px 16px',
            backgroundColor: '#f3f4f6',
            border: '1px solid #e5e7eb',
            borderRadius: '6px',
            color: '#374151',
            fontWeight: '500',
            cursor: 'pointer',
          }}
        >
          New Scan
        </button>
      </div>

      {/* Statistics */}
      <div
        style={{
          display: 'flex',
          gap: '16px',
          marginBottom: '24px',
          flexWrap: 'wrap',
        }}
      >
        <StatCard label="Total" value={stats.total} />
        <StatCard label="Critical" value={stats.critical} color={SEVERITY_LEVELS.CRITICAL.color} />
        <StatCard label="High" value={stats.high} color={SEVERITY_LEVELS.HIGH.color} />
        <StatCard label="Medium" value={stats.medium} color={SEVERITY_LEVELS.MEDIUM.color} />
        <StatCard label="Low" value={stats.low} color={SEVERITY_LEVELS.LOW.color} />
        <StatCard label="Info" value={stats.info} color={SEVERITY_LEVELS.INFO.color} />
      </div>

      {/* Scan metadata */}
      {results.metadata && (
        <div
          style={{
            backgroundColor: '#f9fafb',
            border: '1px solid #e5e7eb',
            borderRadius: '8px',
            padding: '16px',
            marginBottom: '24px',
          }}
        >
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
            {results.metadata.scan_duration && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>Duration: </span>
                <span style={{ fontSize: '14px', color: '#374151', fontWeight: '500' }}>
                  {results.metadata.scan_duration.toFixed(2)}s
                </span>
              </div>
            )}
            {results.metadata.files_scanned && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>Files Scanned: </span>
                <span style={{ fontSize: '14px', color: '#374151', fontWeight: '500' }}>
                  {results.metadata.files_scanned}
                </span>
              </div>
            )}
            {results.metadata.rules_applied && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>Rules Applied: </span>
                <span style={{ fontSize: '14px', color: '#374151', fontWeight: '500' }}>
                  {results.metadata.rules_applied}
                </span>
              </div>
            )}
            {results.metadata.source_url && (
              <div>
                <span style={{ fontSize: '12px', color: '#6b7280' }}>Source: </span>
                <span style={{ fontSize: '14px', color: '#374151', fontWeight: '500' }}>
                  {results.metadata.source_url}
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Filters and search */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '16px',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <FilterButton
            label="All"
            isActive={activeFilter === 'ALL'}
            onClick={() => setActiveFilter('ALL')}
            count={stats.total}
          />
          <FilterButton
            label="Critical"
            isActive={activeFilter === 'CRITICAL'}
            onClick={() => setActiveFilter('CRITICAL')}
            count={stats.critical}
          />
          <FilterButton
            label="High"
            isActive={activeFilter === 'HIGH'}
            onClick={() => setActiveFilter('HIGH')}
            count={stats.high}
          />
          <FilterButton
            label="Medium"
            isActive={activeFilter === 'MEDIUM'}
            onClick={() => setActiveFilter('MEDIUM')}
            count={stats.medium}
          />
          <FilterButton
            label="Low"
            isActive={activeFilter === 'LOW'}
            onClick={() => setActiveFilter('LOW')}
            count={stats.low}
          />
        </div>
        <input
          type="text"
          placeholder="Search vulnerabilities..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            padding: '8px 12px',
            border: '1px solid #e5e7eb',
            borderRadius: '6px',
            fontSize: '14px',
            width: '250px',
            outline: 'none',
          }}
        />
      </div>

      {/* Expand/Collapse controls */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
        <button
          onClick={expandAll}
          style={{
            padding: '6px 12px',
            backgroundColor: 'transparent',
            border: 'none',
            color: '#2563eb',
            fontSize: '14px',
            cursor: 'pointer',
          }}
        >
          Expand All
        </button>
        <button
          onClick={collapseAll}
          style={{
            padding: '6px 12px',
            backgroundColor: 'transparent',
            border: 'none',
            color: '#2563eb',
            fontSize: '14px',
            cursor: 'pointer',
          }}
        >
          Collapse All
        </button>
      </div>

      {/* Vulnerability list */}
      {filteredVulnerabilities.length > 0 ? (
        <div>
          {filteredVulnerabilities.map((vuln, index) => (
            <VulnerabilityCard
              key={`${vuln.rule_id}-${vuln.file_path}-${vuln.line_number}-${index}`}
              vulnerability={vuln}
              isExpanded={expandedIds.has(index)}
              onToggle={() => toggleExpanded(index)}
            />
          ))}
        </div>
      ) : (
        <div
          style={{
            textAlign: 'center',
            padding: '48px',
            backgroundColor: '#f9fafb',
            borderRadius: '8px',
            border: '1px solid #e5e7eb',
          }}
        >
          <svg
            style={{ width: '48px', height: '48px', color: '#16a34a', margin: '0 auto 16px' }}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <h3 style={{ fontSize: '18px', fontWeight: '600', color: '#1f2937', marginBottom: '8px' }}>
            {activeFilter !== 'ALL' || searchQuery
              ? 'No matching vulnerabilities'
              : 'No vulnerabilities found'}
          </h3>
          <p style={{ color: '#6b7280' }}>
            {activeFilter !== 'ALL' || searchQuery
              ? 'Try adjusting your filters or search query.'
              : 'Your code looks secure based on the applied rules.'}
          </p>
        </div>
      )}
    </div>
  );
};

export default Results;
