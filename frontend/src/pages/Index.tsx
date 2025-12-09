import { useState, useEffect } from "react";
import { Crosshair, RotateCcw } from "lucide-react";
import { CyberBackground } from "@/components/CyberBackground";
import { Header } from "@/components/Header";
import { FileUpload } from "@/components/FileUpload";
import { LoadingAnimation } from "@/components/LoadingAnimation";
import { SummaryResults } from "@/components/SummaryResults";
import { LiveMonitoring } from "@/components/LiveMonitoring";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { toast } from "@/hooks/use-toast";
import { predictFile, checkApiHealth, ApiPredictResponse, getLiveStatus } from "@/lib/api";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const Index = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ApiPredictResponse | null>(null);
  const [processingTime, setProcessingTime] = useState<number>(0);
  const [apiConnected, setApiConnected] = useState<boolean | null>(null);
  const [activeTab, setActiveTab] = useState<string>("manual");
  const [isLiveRunning, setIsLiveRunning] = useState<boolean>(false);

  // Check API health on mount and periodically
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/health`);
        if (response.ok) {
          setApiConnected(true);
        } else {
          setApiConnected(false);
        }
      } catch (error) {
        setApiConnected(false);
        // Only show toast on initial failure, not on every retry
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 10000); // Check every 10 seconds
    
    return () => clearInterval(interval);
  }, []);

  // Check live status periodically to disable manual upload when live mode is active
  // Only poll when we need to check (reduce unnecessary requests)
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    
    const checkLiveStatus = async () => {
      try {
        const liveStatus = await getLiveStatus();
        setIsLiveRunning(liveStatus.running);
        
        // If monitoring is stopped, stop polling after this check
        if (!liveStatus.running && interval) {
          clearInterval(interval);
          interval = null;
        }
      } catch (error) {
        // Silently fail if API is not available
        setIsLiveRunning(false);
      }
    };

    // Initial check
    checkLiveStatus();
    
    // Only poll if monitoring might be running (check every 10 seconds, less frequent)
    // This will stop automatically when monitoring is stopped
    interval = setInterval(checkLiveStatus, 10000);
    
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, []);

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setResult(null);
    setProcessingTime(0);
  };

  const handleRunDetection = async () => {
    if (!selectedFile) {
      toast({
        title: "No file selected",
        description: "Please upload a .pcap or .csv file first.",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    const startTime = performance.now();

    try {
      const apiResult = await predictFile(selectedFile);

      const endTime = performance.now();
      const processingTime = (endTime - startTime) / 1000;

      setResult(apiResult);
      setProcessingTime(processingTime);

      // Show success toast with summary
      const summary = apiResult.summary || {};
      const attackCount = summary.ATTACK || 0;
      const anomalyCount = summary.ANOMALY || 0;
      const benignCount = summary.BENIGN || 0;

      if (attackCount > 0) {
        toast({
          title: "Analysis Complete - Threats Detected!",
          description: `Found ${attackCount} attack(s), ${anomalyCount} anomaly(ies), and ${benignCount} benign flow(s).`,
          variant: "destructive",
        });
      } else if (anomalyCount > 0) {
        toast({
          title: "Analysis Complete - Anomalies Detected",
          description: `Found ${anomalyCount} anomaly(ies) and ${benignCount} benign flow(s).`,
        });
      } else {
        toast({
          title: "Analysis Complete",
          description: `All ${benignCount} flow(s) appear to be benign.`,
        });
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "An error occurred while processing the file.";
      toast({
        title: "Analysis Failed",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setResult(null);
    setProcessingTime(0);
  };

  return (
    <div className="min-h-screen bg-background text-foreground relative overflow-hidden">
      <CyberBackground />

      <div className="relative z-10 flex flex-col min-h-screen">
        <Header />

        <main className="flex-1 container mx-auto px-4 py-8 md:py-12">
          <div className="max-w-4xl mx-auto space-y-8">
            {/* Title Section */}
            <div className="text-center space-y-4 animate-fade-in">
              <h2 className="text-3xl md:text-4xl font-display font-bold tracking-wide">
                Network Traffic <span className="text-primary text-glow-cyan">Analysis</span>
              </h2>
              <p className="text-muted-foreground max-w-xl mx-auto">
                Upload network capture files or monitor live traffic for real-time threat detection powered by
                advanced machine learning algorithms.
              </p>
            </div>

            {/* Mode Selector Tabs */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid w-full grid-cols-2 mb-6">
                <TabsTrigger value="manual" className="text-base">
                  Manual Analysis
                </TabsTrigger>
                <TabsTrigger value="live" className="text-base">
                  Live Monitoring
                </TabsTrigger>
              </TabsList>

              {/* Manual Upload Tab */}
              <TabsContent value="manual" className="space-y-6 animate-fade-in">
                {!isAnalyzing && !result && (
                  <Card className="animate-fade-in" style={{ animationDelay: "0.1s" }}>
                    <CardHeader>
                      <CardTitle className="text-lg font-display flex items-center space-x-2">
                        <Crosshair className="w-5 h-5 text-primary" />
                        <span>Upload Network Capture</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6">
                      {isLiveRunning && (
                        <div className="p-3 bg-status-anomaly/10 border border-status-anomaly/30 rounded-lg text-center">
                          <p className="text-sm text-status-anomaly">
                            ⚠️ Live monitoring is active. Manual upload is disabled.
                          </p>
                        </div>
                      )}
                      <FileUpload
                        onFileSelect={handleFileSelect}
                        selectedFile={selectedFile}
                        disabled={isAnalyzing || isLiveRunning}
                      />

                      {apiConnected === false && (
                        <div className="p-3 bg-status-attack/10 border border-status-attack/30 rounded-lg text-center">
                          <p className="text-sm text-status-attack">
                            ⚠️ API server not connected. Please start the backend server.
                          </p>
                        </div>
                      )}
                      <Button
                        variant="cyber"
                        size="xl"
                        className="w-full"
                        onClick={handleRunDetection}
                        disabled={!selectedFile || isAnalyzing || apiConnected === false || isLiveRunning}
                      >
                        <Crosshair className="w-5 h-5" />
                        Run Detection
                      </Button>
                    </CardContent>
                  </Card>
                )}

                {/* Loading State */}
                {isAnalyzing && (
                  <Card className="animate-fade-in">
                    <CardContent className="py-4">
                      <LoadingAnimation />
                    </CardContent>
                  </Card>
                )}

                {/* Results */}
                {result && (
                  <div className="space-y-6">
                    <SummaryResults result={result} processingTime={processingTime} />

                    <div className="flex justify-center">
                      <Button variant="outline" size="lg" onClick={handleReset}>
                        <RotateCcw className="w-4 h-4" />
                        Analyze Another File
                      </Button>
                    </div>
                  </div>
                )}
              </TabsContent>

              {/* Live Monitoring Tab */}
              <TabsContent value="live" className="space-y-6 animate-fade-in">
                <LiveMonitoring />
              </TabsContent>
            </Tabs>
          </div>
        </main>

        {/* Footer */}
        <footer className="relative z-10 border-t border-border/50 bg-background/80 backdrop-blur-sm py-4">
          <div className="container mx-auto px-4 text-center">
            <p className="text-xs text-muted-foreground font-mono">
              AI-IDS v1.0 • Powered by Machine Learning • © 2025
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Index;
