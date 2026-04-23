const express = require("express");
const app = express();
app.use(express.json());

const db = {
  getAccount: (id) => ({ id, balance: 100 }), // Everyone starts with $100
  save: (account) => {},
};

app.post("/api/transfer-funds", (req, res) => {
  const { fromAccountId, toAccountId, amount } = req.body;

  if (req.user.accountId !== fromAccountId) {
    return res.status(403).send("Unauthorized");
  }

  const sourceAccount = db.getAccount(fromAccountId);
  const destAccount = db.getAccount(toAccountId);

  // Security check: Ensure they have enough money
  if (sourceAccount.balance < amount) {
    return res.status(400).send("Insufficient funds");
  }

  sourceAccount.balance -= amount;
  destAccount.balance += amount;

  db.save(sourceAccount);
  db.save(destAccount);

  res.send({
    message: "Transfer complete",
    newBalance: sourceAccount.balance,
  });
});
