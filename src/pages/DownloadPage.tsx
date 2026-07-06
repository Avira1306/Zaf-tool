import { Helmet } from 'react-helmet-async';

const DOWNLOAD_URL = "https://xcabkqfvcnuzfjkthfjw.supabase.co/storage/v1/object/public/zaf-releases/ZAF_Tools_v5.0.0.msi";

export default function DownloadPage() {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      padding: '20px',
    }}>
      <Helmet>
        <title>Download ZAF Tools - FDD Automation Suite</title>
      </Helmet>

      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '16px',
        padding: '48px',
        maxWidth: '480px',
        width: '100%',
        textAlign: 'center',
      }}>
        <h1 style={{
          color: '#f8fafc',
          fontSize: '28px',
          fontWeight: 700,
          margin: '0 0 8px',
        }}>
          Download ZAF Tools
        </h1>
        <p style={{
          color: '#94a3b8',
          fontSize: '15px',
          margin: '0 0 32px',
          lineHeight: 1.5,
        }}>
          Version 5.0.0 — Financial Due Diligence Automation Suite
        </p>

        <a
          href={DOWNLOAD_URL}
          style={{
            display: 'inline-block',
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            color: '#fff',
            padding: '14px 48px',
            borderRadius: '8px',
            fontSize: '16px',
            fontWeight: 600,
            textDecoration: 'none',
            marginBottom: '12px',
            transition: 'transform 0.2s',
          }}
          onMouseOver={(e) => e.currentTarget.style.transform = 'scale(1.03)'}
          onMouseOut={(e) => e.currentTarget.style.transform = 'scale(1)'}
        >
          Download Now (7.9 MB)
        </a>

        <p style={{
          color: '#64748b',
          fontSize: '13px',
          margin: '0',
        }}>
          Windows • MSI Installer • Excel Add-in
        </p>

        <div style={{
          marginTop: '32px',
          padding: '16px',
          background: '#0f172a',
          borderRadius: '8px',
          textAlign: 'left',
        }}>
          <p style={{ color: '#cbd5e1', fontSize: '13px', margin: '0 0 8px', fontWeight: 600 }}>
            Installation Instructions:
          </p>
          <ol style={{ color: '#94a3b8', fontSize: '13px', margin: '0', paddingLeft: '20px', lineHeight: 1.8 }}>
            <li>Download and run the MSI installer</li>
            <li>Open Excel — you'll see the ZAF Tools ribbon</li>
            <li>Click ZAF AI tab → AI Mode → Login</li>
            <li>Sign up or log in to start your trial</li>
          </ol>
        </div>
      </div>

      <p style={{
        color: '#475569',
        fontSize: '12px',
        marginTop: '24px',
      }}>
        Need help? Contact <a href="mailto:support@zaftool.com" style={{ color: '#6366f1' }}>support@zaftool.com</a>
      </p>
    </div>
  );
}
