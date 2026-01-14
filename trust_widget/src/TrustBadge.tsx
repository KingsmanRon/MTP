/**
 * Machine Trust Protocol - Trust Badge Widget
 *
 * A lightweight React component that displays the verification status
 * of an AI agent. Shows a "Verified Shield" with trust score to end-users.
 *
 * Usage:
 *   <TrustBadge agentId="uuid-here" apiUrl="https://api.mtp.dev" />
 */

import React, { useEffect, useState, useCallback } from 'react';

// =============================================================================
// TYPES
// =============================================================================

interface AgentInfo {
  agent_id: string;
  name: string;
  organization_name: string;
  trust_score: number;
  status: 'active' | 'suspended' | 'revoked' | 'pending_verification';
  is_verified: boolean;
  verified_since: string | null;
  total_actions: number;
  last_action_at: string | null;
}

interface TrustBadgeProps {
  /** UUID of the agent to display */
  agentId: string;
  /** MTP API URL */
  apiUrl?: string;
  /** Badge size variant */
  size?: 'small' | 'medium' | 'large';
  /** Show detailed information on hover */
  showDetails?: boolean;
  /** Custom CSS class */
  className?: string;
  /** Refresh interval in milliseconds (0 to disable) */
  refreshInterval?: number;
  /** Callback when badge is clicked */
  onClick?: (agentInfo: AgentInfo) => void;
}

// =============================================================================
// STYLES
// =============================================================================

const styles = {
  container: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    borderRadius: '8px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontSize: '14px',
    cursor: 'pointer',
    transition: 'all 0.2s ease',
    border: '1px solid',
  },
  verified: {
    backgroundColor: '#f0fdf4',
    borderColor: '#22c55e',
    color: '#15803d',
  },
  unverified: {
    backgroundColor: '#fef2f2',
    borderColor: '#ef4444',
    color: '#dc2626',
  },
  pending: {
    backgroundColor: '#fffbeb',
    borderColor: '#f59e0b',
    color: '#d97706',
  },
  loading: {
    backgroundColor: '#f3f4f6',
    borderColor: '#d1d5db',
    color: '#6b7280',
  },
  shieldIcon: {
    width: '20px',
    height: '20px',
  },
  scoreCircle: {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontWeight: 'bold',
    fontSize: '12px',
  },
  tooltip: {
    position: 'absolute' as const,
    top: '100%',
    left: '50%',
    transform: 'translateX(-50%)',
    marginTop: '8px',
    padding: '12px 16px',
    backgroundColor: '#1f2937',
    color: '#ffffff',
    borderRadius: '8px',
    fontSize: '12px',
    whiteSpace: 'nowrap' as const,
    zIndex: 1000,
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
  },
};

// =============================================================================
// ICONS
// =============================================================================

const ShieldCheckIcon: React.FC<{ color: string }> = ({ color }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill={color}
    style={styles.shieldIcon}
  >
    <path
      fillRule="evenodd"
      d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516 11.209 11.209 0 01-7.877-3.08zm3.044 7.89a.75.75 0 10-1.06-1.06l-3.75 3.75-1.5-1.5a.75.75 0 00-1.06 1.06l2.03 2.03a.75.75 0 001.06 0l4.28-4.28z"
      clipRule="evenodd"
    />
  </svg>
);

const ShieldExclamationIcon: React.FC<{ color: string }> = ({ color }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill={color}
    style={styles.shieldIcon}
  >
    <path
      fillRule="evenodd"
      d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.942 4.064 10.933 9.563 12.348a.749.749 0 00.374 0c5.499-1.415 9.563-6.406 9.563-12.348 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.516 11.209 11.209 0 01-7.877-3.08zM12 8.25a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V9a.75.75 0 01.75-.75zM12 15a.75.75 0 100 1.5.75.75 0 000-1.5z"
      clipRule="evenodd"
    />
  </svg>
);

const LoadingSpinner: React.FC = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    style={{ ...styles.shieldIcon, animation: 'spin 1s linear infinite' }}
  >
    <circle cx="12" cy="12" r="10" strokeOpacity="0.25" />
    <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round" />
  </svg>
);

// =============================================================================
// COMPONENT
// =============================================================================

export const TrustBadge: React.FC<TrustBadgeProps> = ({
  agentId,
  apiUrl = 'https://api.mtp.dev',
  size = 'medium',
  showDetails = true,
  className = '',
  refreshInterval = 60000,
  onClick,
}) => {
  const [agentInfo, setAgentInfo] = useState<AgentInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showTooltip, setShowTooltip] = useState(false);

  const fetchAgentInfo = useCallback(async () => {
    try {
      const response = await fetch(`${apiUrl}/public/agent/${agentId}`);

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Agent not found');
        }
        throw new Error('Failed to fetch agent info');
      }

      const data: AgentInfo = await response.json();
      setAgentInfo(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [agentId, apiUrl]);

  useEffect(() => {
    fetchAgentInfo();

    if (refreshInterval > 0) {
      const interval = setInterval(fetchAgentInfo, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [fetchAgentInfo, refreshInterval]);

  const getStatusStyle = () => {
    if (loading) return styles.loading;
    if (error || !agentInfo) return styles.unverified;
    if (agentInfo.is_verified) return styles.verified;
    if (agentInfo.status === 'pending_verification') return styles.pending;
    return styles.unverified;
  };

  const getScoreColor = (score: number): string => {
    if (score >= 70) return '#22c55e';
    if (score >= 40) return '#f59e0b';
    return '#ef4444';
  };

  const handleClick = () => {
    if (onClick && agentInfo) {
      onClick(agentInfo);
    }
  };

  const formatDate = (dateStr: string | null): string => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString();
  };

  return (
    <div
      style={{ ...styles.container, ...getStatusStyle() }}
      className={className}
      onClick={handleClick}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
      role="button"
      tabIndex={0}
      aria-label={
        loading
          ? 'Loading agent verification status'
          : agentInfo?.is_verified
            ? `Verified agent: ${agentInfo.name}`
            : 'Unverified agent'
      }
    >
      {/* Icon */}
      {loading ? (
        <LoadingSpinner />
      ) : agentInfo?.is_verified ? (
        <ShieldCheckIcon color="#22c55e" />
      ) : (
        <ShieldExclamationIcon color={error ? '#ef4444' : '#f59e0b'} />
      )}

      {/* Status Text */}
      <span>
        {loading
          ? 'Verifying...'
          : error
            ? 'Unverified'
            : agentInfo?.is_verified
              ? 'MTP Verified'
              : agentInfo?.status === 'pending_verification'
                ? 'Pending'
                : 'Not Verified'}
      </span>

      {/* Trust Score */}
      {!loading && agentInfo && (
        <div
          style={{
            ...styles.scoreCircle,
            backgroundColor: `${getScoreColor(agentInfo.trust_score)}20`,
            color: getScoreColor(agentInfo.trust_score),
          }}
        >
          {agentInfo.trust_score}
        </div>
      )}

      {/* Tooltip */}
      {showDetails && showTooltip && agentInfo && (
        <div style={styles.tooltip}>
          <div><strong>{agentInfo.name}</strong></div>
          <div style={{ opacity: 0.8 }}>{agentInfo.organization_name}</div>
          <div style={{ marginTop: '8px', borderTop: '1px solid #374151', paddingTop: '8px' }}>
            <div>Trust Score: {agentInfo.trust_score}/100</div>
            <div>Total Actions: {agentInfo.total_actions.toLocaleString()}</div>
            <div>Verified Since: {formatDate(agentInfo.verified_since)}</div>
            <div>Last Active: {formatDate(agentInfo.last_action_at)}</div>
          </div>
        </div>
      )}
    </div>
  );
};

// =============================================================================
// EXPORTS
// =============================================================================

export default TrustBadge;
export type { TrustBadgeProps, AgentInfo };
