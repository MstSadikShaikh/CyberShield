import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { UrlScanner } from './components/UrlScanner';
import { ScanResult } from './components/ScanResult';
import { ScanHistory } from './components/ScanHistory';
import { SecurityEducation } from './components/SecurityEducation';
import { AboutSection } from './components/AboutSection';
import { Footer } from './components/Footer';
import { apiService } from './services/api';

export function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [currentScan, setCurrentScan] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);
  const [healthData, setHealthData] = useState(null);
  const [lastScannedUrl, setLastScannedUrl] = useState('');

  // Fetch backend health and ONNX status on mount and every 30 seconds
  const checkHealth = async () => {
    try {
      const data = await apiService.getHealth();
      setHealthData(data);
    } catch (err) {
      setHealthData({ status: 'DOWN', databaseStatus: 'DISCONNECTED', modelStatus: 'DISCONNECTED' });
    }
  };

  useEffect(() => {
    checkHealth();
    const timer = setInterval(checkHealth, 30000);
    return () => clearInterval(timer);
  }, []);

  const handleScan = async (url) => {
    setIsScanning(true);
    setError(null);
    try {
      const result = await apiService.scanUrl(url);
      setCurrentScan(result);
      setLastScannedUrl(url);
      setActiveTab('results');
      // Refresh health probe in case DB activity updated status
      checkHealth();
    } catch (err) {
      setError(err.message || 'An unexpected error occurred during scan.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectFromHistory = (scanItem) => {
    setCurrentScan(scanItem);
    setActiveTab('results');
  };

  return (
    <div className="app-container">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        healthData={healthData}
        isScanning={isScanning}
      />

      <main className="main-content">
        {activeTab === 'scanner' && (
          <UrlScanner
            onScan={handleScan}
            isScanning={isScanning}
            error={error}
            lastScannedUrl={lastScannedUrl}
          />
        )}

        {activeTab === 'results' && (
          <ScanResult
            scanData={currentScan}
            onScanAgain={() => setActiveTab('scanner')}
          />
        )}

        {activeTab === 'history' && (
          <ScanHistory onSelectScan={handleSelectFromHistory} />
        )}

        {activeTab === 'education' && <SecurityEducation />}

        {activeTab === 'about' && <AboutSection healthData={healthData} />}
      </main>

      <Footer />
    </div>
  );
}

export default App;
