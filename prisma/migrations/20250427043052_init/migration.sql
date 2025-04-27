-- CreateTable
CREATE TABLE "Company" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "User" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "company_id" INTEGER NOT NULL,
    "first_time" BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT "User_company_id_fkey" FOREIGN KEY ("company_id") REFERENCES "Company" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Category" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "company_id" INTEGER NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT "Category_company_id_fkey" FOREIGN KEY ("company_id") REFERENCES "Company" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Transaction" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "description" TEXT NOT NULL,
    "category_id" INTEGER NOT NULL,
    "value" REAL NOT NULL,
    "type" TEXT NOT NULL,
    "date" DATETIME NOT NULL,
    "company_id" INTEGER NOT NULL,
    "created_by" INTEGER NOT NULL,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Transaction_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "Category" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Transaction_company_id_fkey" FOREIGN KEY ("company_id") REFERENCES "Company" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Transaction_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
