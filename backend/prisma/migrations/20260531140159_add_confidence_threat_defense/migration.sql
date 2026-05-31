-- CreateTable
CREATE TABLE "ThreatModel" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "assets" TEXT NOT NULL DEFAULT '[]',
    "attackers" TEXT NOT NULL DEFAULT '[]',
    "attackSurfaces" TEXT NOT NULL DEFAULT '[]',
    "controls" TEXT NOT NULL DEFAULT '[]',
    "gaps" TEXT NOT NULL DEFAULT '[]',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ThreatModel_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "DefenseLayer" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'unknown',
    "issuesCount" INTEGER NOT NULL DEFAULT 0,
    "summary" TEXT NOT NULL DEFAULT '',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "DefenseLayer_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "RuleConfig" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "ruleId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "severityOverride" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "confidence" TEXT NOT NULL DEFAULT 'medium',
    "filePath" TEXT,
    "url" TEXT,
    "line" INTEGER,
    "evidenceMasked" TEXT,
    "description" TEXT NOT NULL,
    "impact" TEXT NOT NULL,
    "attackScenarioDefensive" TEXT,
    "remediation" TEXT NOT NULL,
    "safeExample" TEXT,
    "fixPrompt" TEXT,
    "testSuggestion" TEXT,
    "reference" TEXT,
    "status" TEXT NOT NULL DEFAULT 'open',
    "userNote" TEXT,
    "occurrences" INTEGER NOT NULL DEFAULT 1,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Finding" ("category", "createdAt", "description", "evidenceMasked", "filePath", "id", "impact", "line", "reference", "remediation", "ruleId", "safeExample", "scanId", "severity", "status", "title", "url") SELECT "category", "createdAt", "description", "evidenceMasked", "filePath", "id", "impact", "line", "reference", "remediation", "ruleId", "safeExample", "scanId", "severity", "status", "title", "url" FROM "Finding";
DROP TABLE "Finding";
ALTER TABLE "new_Finding" RENAME TO "Finding";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE UNIQUE INDEX "ThreatModel_scanId_key" ON "ThreatModel"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "RuleConfig_ruleId_key" ON "RuleConfig"("ruleId");
