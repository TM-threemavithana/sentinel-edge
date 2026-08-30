"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

interface AuthContextValue {
  sessionExpired: boolean;
}

const AuthContext = createContext<AuthContextValue>({ sessionExpired: false });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [sessionExpired, setSessionExpired] = useState(false);

  useEffect(() => {
    function handleExpired() {
      setSessionExpired(true);
      setTimeout(() => {
        window.location.href = "/login?expired=1";
      }, 1500);
    }
    window.addEventListener("sentinel:session-expired", handleExpired);
    return () => window.removeEventListener("sentinel:session-expired", handleExpired);
  }, []);

  return (
    <AuthContext.Provider value={{ sessionExpired }}>
      {sessionExpired && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, zIndex: 9999,
          background: "rgba(220, 38, 38, 0.95)", color: "white",
          padding: "12px 24px", textAlign: "center", fontSize: "14px",
        }}>
          Your session has expired. Redirecting to login...
        </div>
      )}
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
