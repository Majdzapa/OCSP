import { useState, useEffect, useCallback } from 'react';
import { getDashboardStats } from '../api/client';
/**
 * Polls the dashboard stats endpoint every {@link intervalMs} milliseconds.
 * Returns the latest data, loading state, and any error.
 */
export function useDashboardStats(intervalMs = 5000) {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const fetch = useCallback(async () => {
        try {
            const data = await getDashboardStats();
            setStats(data);
            setError(null);
        }
        catch (e) {
            setError(e instanceof Error ? e.message : 'Failed to load stats');
        }
        finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => {
        fetch();
        const id = setInterval(fetch, intervalMs);
        return () => clearInterval(id);
    }, [fetch, intervalMs]);
    return { stats, loading, error, refresh: fetch };
}
