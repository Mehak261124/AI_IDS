import { useState, useEffect, useCallback } from "react";
import { Play, Square, Activity, Shield, AlertTriangle, Skull, FileText, RefreshCw, Download, RotateCcw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { startLiveMonitoring, stopLiveMonitoring, getLiveStatus, LiveStatusResponse, getDownloadUrl } from "@/lib/api";
import { SummaryResults } from "@/components/SummaryResults";
import { ApiPredictResponse } from "@/lib/api";
import { toast } from "@/hooks/use-toast";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export const LiveMonitoring = () => {
  const [status, setStatus] = useState<LiveStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastFlowCount, setLastFlowCount] = useState<number>(0);
  const [showResults, setShowResults] = useState<boolean>(false);
  const [resultData, setResultData] = useState<ApiPredictResponse | null>(null);
  const [hasStartedSession, setHasStartedSession] = useState<boolean>(false);

  // Poll for status updates every 5 seconds (ONLY when monitoring is actively running)
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;

    const fetchStatus = async () => {
      try {
        const liveStatus = await getLiveStatus();
        
        // Always update status when polling (only happens when running)
        setStatus((prevStatus) => {
          const previousFlowCount = prevStatus?.flows ?? 0;
          
          // Show toast when new flows are detected (only during active monitoring)
          if (liveStatus.running && liveStatus.flows > previousFlowCount && previousFlowCount > 0) {
            const newFlows = liveStatus.flows - previousFlowCount;
            toast({
              title: "Processing flows...",
              description: `${newFlows} new flow(s) detected and being analyzed`,
            });
          }
          
          return liveStatus;
        });
        
        setLastFlowCount((prev) => {
          const currentFlows = liveStatus.flows;
          return currentFlows > prev ? currentFlows : prev;
        });
        
        // If monitoring stopped, stop polling
        if (!liveStatus.running) {
          if (interval) {
            clearInterval(interval);
            interval = null;
          }
        }
      } catch (error) {
        console.error("Failed to fetch live status:", error);
      }
    };

    // Only start polling if monitoring is currently running
    const currentlyRunning = status?.running ?? false;
    
    if (currentlyRunning) {
      // Initial fetch
      fetchStatus();
      
      // Set up polling interval
      interval = setInterval(() => {
        fetchStatus();
      }, 5000);
    } else {
      // If not running, just do one initial check (for initial page load)
      // This won't poll continuously
      if (status === null) {
        fetchStatus();
      }
    }

    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [status?.running]); // Restart effect when running status changes

  const handleStart = async () => {
    setIsLoading(true);
    try {
      await startLiveMonitoring();
      setHasStartedSession(true); // Mark that we've started a session
      setShowResults(false); // Clear any previous results
      setResultData(null);
      
      toast({
        title: "Live capture started",
        description: "Network monitoring is now active",
      });
      
      // Fetch updated status - polling will start automatically via useEffect when isRunning becomes true
      const liveStatus = await getLiveStatus();
      setStatus(liveStatus);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Failed to start live monitoring";
      toast({
        title: "Failed to start monitoring",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleStop = async () => {
    setIsLoading(true);
    try {
      await stopLiveMonitoring();
      
      toast({
        title: "Live capture stopped",
        description: "Network monitoring has been stopped",
      });
      
      // Wait a moment for final processing, then fetch updated status ONCE
      await new Promise(resolve => setTimeout(resolve, 1500));
      const liveStatus = await getLiveStatus();
      setStatus(liveStatus);
      
      // Convert live status to result format for display
      if (liveStatus.flows > 0 && liveStatus.all_flows) {
        const result: ApiPredictResponse = {
          status: "success",
          file_type: "live",
          filename: liveStatus.last_capture || "live_capture",
          file_size_bytes: 0,
          total_flows: liveStatus.flows,
          summary: liveStatus.summary,
          attack_types: liveStatus.attack_types || {},
          download_csv: "live/live_predictions.csv",
          data_preview: liveStatus.all_flows.slice(0, 10),
          all_flows: liveStatus.all_flows
        };
        setResultData(result);
        setShowResults(true);
        
        toast({
          title: "Results ready",
          description: `Analysis complete: ${liveStatus.flows} flow(s) processed`,
        });
      }
      
      // After stopping, the polling will automatically stop because isRunning will be false
      // and hasStartedSession will remain true, but the interval check will prevent new polling
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Failed to stop live monitoring";
      toast({
        title: "Failed to stop monitoring",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const isRunning = status?.running ?? false;
  const flows = status?.flows ?? 0;
  const summary = status?.summary ?? { BENIGN: 0, ANOMALY: 0, ATTACK: 0 };
  const lastCapture = status?.last_capture;

  // Status indicator color
  const getStatusColor = () => {
    if (isRunning) return "bg-status-benign border-status-benign";
    // Show processing (orange) only if we just stopped and might be processing final batch
    // After a short delay, show stopped
    if (!isRunning && isLoading) return "bg-status-anomaly border-status-anomaly";
    return "bg-status-attack border-status-attack";
  };

  const getStatusText = () => {
    if (isRunning) return "Capturing...";
    if (!isRunning && isLoading) return "Processing...";
    return "Stopped";
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Control Panel */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-display flex items-center space-x-2">
            <Activity className="w-5 h-5 text-primary" />
            <span>Live Network Monitoring</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Status Indicator */}
          <div className="flex items-center justify-center space-x-4">
            <div className={cn(
              "w-4 h-4 rounded-full border-2 transition-all duration-300",
              getStatusColor(),
              isRunning && "animate-pulse"
            )} />
            <span className="text-sm font-mono uppercase tracking-wider">
              {getStatusText()}
            </span>
          </div>

          {/* Control Buttons */}
          <div className="flex gap-4 justify-center">
            <Button
              variant="cyber"
              size="lg"
              onClick={handleStart}
              disabled={isRunning || isLoading}
              className="min-w-[160px]"
            >
              <Play className="w-5 h-5 mr-2" />
              Start Monitoring
            </Button>
            <Button
              variant="outline"
              size="lg"
              onClick={handleStop}
              disabled={!isRunning || isLoading}
              className="min-w-[160px]"
            >
              <Square className="w-5 h-5 mr-2" />
              Stop Monitoring
            </Button>
          </div>

          {/* Real-time Stats - Only show if monitoring is running or we've started a session */}
          {status && (isRunning || hasStartedSession) && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
              <Card className="bg-status-benign/10 border-status-benign/30">
                <CardContent className="p-4 text-center">
                  <Shield className="w-8 h-8 text-status-benign mx-auto mb-2" />
                  <p className="text-3xl font-bold text-status-benign">{summary.BENIGN}</p>
                  <p className="text-sm text-muted-foreground">BENIGN</p>
                </CardContent>
              </Card>

              <Card className="bg-status-anomaly/10 border-status-anomaly/30">
                <CardContent className="p-4 text-center">
                  <AlertTriangle className="w-8 h-8 text-status-anomaly mx-auto mb-2" />
                  <p className="text-3xl font-bold text-status-anomaly">{summary.ANOMALY}</p>
                  <p className="text-sm text-muted-foreground">ANOMALY</p>
                </CardContent>
              </Card>

              <Card className="bg-status-attack/10 border-status-attack/30">
                <CardContent className="p-4 text-center">
                  <Skull className="w-8 h-8 text-status-attack mx-auto mb-2" />
                  <p className="text-3xl font-bold text-status-attack">{summary.ATTACK}</p>
                  <p className="text-sm text-muted-foreground">ATTACK</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Summary Information - Show when stopped but no results displayed yet (only if we started a session) */}
          {!isRunning && hasStartedSession && (lastCapture || flows > 0) && !showResults && (
            <Card className="bg-card/50 mt-6">
              <CardHeader className="py-4">
                <CardTitle className="text-sm text-muted-foreground font-mono uppercase tracking-wider flex items-center space-x-2">
                  <FileText className="w-4 h-4" />
                  <span>Latest Capture Summary</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="py-4 space-y-3">
                {lastCapture && (
                  <div className="flex items-center space-x-3 p-3 bg-secondary/50 rounded-lg">
                    <FileText className="w-5 h-5 text-primary" />
                    <div>
                      <p className="text-xs text-muted-foreground">Latest capture file</p>
                      <p className="text-sm font-mono">{lastCapture}</p>
                    </div>
                  </div>
                )}
                <div className="flex items-center space-x-3 p-3 bg-secondary/50 rounded-lg">
                  <Activity className="w-5 h-5 text-primary" />
                  <div>
                    <p className="text-xs text-muted-foreground">Total flows processed</p>
                    <p className="text-sm font-mono">{flows}</p>
                  </div>
                </div>
                <div className="flex items-center space-x-3 p-3 bg-secondary/50 rounded-lg">
                  <RefreshCw className="w-5 h-5 text-primary" />
                  <div>
                    <p className="text-xs text-muted-foreground">Prediction summary</p>
                    <p className="text-sm font-mono">
                      Benign: {summary.BENIGN} | Anomaly: {summary.ANOMALY} | Attack: {summary.ATTACK}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      {/* Detailed Results Display - Similar to Manual Analysis */}
      {showResults && resultData && (
        <div className="space-y-6 animate-fade-in">
          <SummaryResults result={resultData} processingTime={0} />
          
          <div className="flex justify-center gap-4">
            <Button variant="outline" size="lg" onClick={() => {
              setShowResults(false);
              setResultData(null);
            }}>
              <RotateCcw className="w-4 h-4 mr-2" />
              Back to Monitoring
            </Button>
            <Button 
              variant="outline" 
              size="lg" 
              onClick={() => {
                const url = getDownloadUrl('live_predictions.csv');
                window.open(url, '_blank');
                toast({
                  title: "Download Started",
                  description: "CSV file download initiated",
                });
              }}
            >
              <Download className="w-4 h-4 mr-2" />
              Download Results CSV
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

