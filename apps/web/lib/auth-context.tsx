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
        <div className="session-banner" role="status">
          Your session has expired. Redirecting to sign in…
        </div>
      )}
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
