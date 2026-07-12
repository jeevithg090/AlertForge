'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { login } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await login(email, password);
      localStorage.setItem('sf_token', data.token);
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-warroom-bg text-gray-200 flex items-center justify-center">
      <div className="bg-warroom-surface border border-warroom-border rounded-lg p-8 w-full max-w-sm">
        <h1 className="text-xl font-bold text-center mb-6">SentinelForge</h1>
        <p className="text-sm text-gray-400 text-center mb-6">Autonomous SOC War Room</p>
        {error && (
          <div className="bg-red-500/20 border border-red-500/40 text-red-300 text-sm rounded p-2 mb-4 text-center">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="admin@sentinelforge.local"
              className="w-full bg-warroom-bg border border-warroom-border rounded px-3 py-2 text-sm focus:outline-none focus:border-warroom-tool"
              required
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="changeme-admin"
              className="w-full bg-warroom-bg border border-warroom-border rounded px-3 py-2 text-sm focus:outline-none focus:border-warroom-tool"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 px-4 bg-warroom-success/20 border border-warroom-success/40 rounded text-sm font-bold text-warroom-success hover:bg-warroom-success/30 transition disabled:opacity-50"
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
