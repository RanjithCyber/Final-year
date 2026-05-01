"use strict";

/////////////////////////////////////////////////
/////////////////////////////////////////////////
// BANKIST APP

// Data
const account1 = {
  owner: "Jonas Schmedtmann",
  movements: [200, 450, -400, 3000, -650, -130, 70, 1300],
  interestRate: 1.2, // %
  pin: 1111,
};

const account2 = {
  owner: "Jessica Davis",
  movements: [5000, 3400, -150, -790, -3210, -1000, 8500, -30],
  interestRate: 1.5,
  pin: 2222,
};

const account3 = {
  owner: "Steven Thomas Williams",
  movements: [200, -200, 340, -300, -20, 50, 400, -460],
  interestRate: 0.7,
  pin: 3333,
};

const account4 = {
  owner: "Sarah Smith",
  movements: [430, 1000, 700, 50, 90],
  interestRate: 1,
  pin: 4444,
};

const accounts = [account1, account2, account3, account4];

// Elements
const labelWelcome = document.querySelector(".welcome");
const labelDate = document.querySelector(".date");
const labelBalance = document.querySelector(".balance__value");
const labelSumIn = document.querySelector(".summary__value--in");
const labelSumOut = document.querySelector(".summary__value--out");
const labelSumInterest = document.querySelector(".summary__value--interest");
const labelTimer = document.querySelector(".timer");

const containerApp = document.querySelector(".app");
const containerMovements = document.querySelector(".movements");

const btnLogin = document.querySelector(".login__btn");
const btnTransfer = document.querySelector(".form__btn--transfer");
const btnLoan = document.querySelector(".form__btn--loan");
const btnClose = document.querySelector(".form__btn--close");
const btnSort = document.querySelector(".btn--sort");

const inputLoginUsername = document.querySelector(".login__input--user");
const inputLoginPin = document.querySelector(".login__input--pin");
const inputTransferTo = document.querySelector(".form__input--to");
const inputTransferAmount = document.querySelector(".form__input--amount");
const inputLoanAmount = document.querySelector(".form__input--loan-amount");
const inputCloseUsername = document.querySelector(".form__input--user");
const inputClosePin = document.querySelector(".form__input--pin");

const displayMovements = function (movements, sort = false) {
  containerMovements.innerHTML = "";
  const movs = sort ? movements.slice().sort((a, b) => a - b) : movements;

  movs.forEach(function (mov, i) {
    const type = mov > 0 ? "deposit" : "withdrawal";
    const html = `
     <div class="movements__row">
          <div class="movements__type movements__type--${type}">${
      i + 1
    } ${type}</div>
          <div class="movements__value">${mov}€</div>
        </div>`;
    containerMovements.insertAdjacentHTML("afterbegin", html);
  });
};
const calcDisplaySummary = function (acc) {
  const incomes = acc.movements
    .filter((mov) => mov > 0)
    .reduce((acc, mov) => acc + mov);
  labelSumIn.textContent = `${incomes}€`;

  const out = acc.movements
    .filter((mov) => mov < 0)
    .reduce((acc, mov) => acc + mov, 0);
  labelSumOut.textContent = `${Math.abs(out)}€`;
  const interest = acc.movements
    .filter((mov) => mov > 0)
    .map((deposit) => (deposit * acc.interestRate) / 100)
    .filter((int, i, arr) => {
      return int >= 1;
    })
    .reduce((acc, int) => acc + int, 0);
  labelSumInterest.textContent = `${interest}€`;
};
const createUsernames = function (accs) {
  accs.forEach(function (acc) {
    acc.username = acc.owner
      .toLowerCase()
      .split(" ")
      .map((name) => name[0])
      .join("");
  });
};

const calcDisplayBalance = function (acc) {
  acc.balance = acc.movements.reduce((acc, mov) => acc + mov, 0);
  labelBalance.textContent = `${acc.balance}€`;
};

createUsernames(accounts);
const updateUI = function (acc) {
  // Dispaly Movements
  displayMovements(acc.movements);

  // Display Balance
  calcDisplayBalance(currentAccount);

  // Dispaly Summary
  calcDisplaySummary(currentAccount);
};
// ADD LOGIN EVENT HANDLER
let currentAccount;
btnLogin.addEventListener("click", function (e) {
  e.preventDefault();
  currentAccount = accounts.find(
    (acc) => acc.username === inputLoginUsername.value
  );

  if (currentAccount?.pin === Number(inputLoginPin.value)) {
    // Diplay UI and message
    labelWelcome.textContent = `Welcome Back, ${
      currentAccount.owner.split(" ")[0]
    }`;
    containerApp.style.opacity = 100;

    // Clearing the Field After Loged In
    inputLoginUsername.value = inputLoginPin.value = "";
    inputLoginPin.blur();

    // Update UI
    updateUI(currentAccount);
  }
});
// Implemeting Transfers
btnTransfer.addEventListener("click", function (e) {
  e.preventDefault();
  const amount = Number(inputTransferAmount.value);
  const recevierAcc = accounts.find(
    (acc) => acc.username === inputTransferTo.value
  );
  inputTransferAmount.value = inputTransferTo.value = "";

  if (
    amount > 0 &&
    recevierAcc &&
    currentAccount.balance >= amount &&
    recevierAcc?.username != currentAccount.username
  ) {
    // Doing Transfer
    currentAccount.movements.push(-amount);
    recevierAcc.movements.push(amount);

    // Update UI
    updateUI(currentAccount);
  }
});
btnLoan.addEventListener("click", function (e) {
  e.preventDefault();
  const amount = Number(inputLoanAmount.value);
  if (
    amount > 0 &&
    currentAccount.movements.some((mov) => mov >= amount * 0.1)
  ) {
    //Add movement
    currentAccount.movements.push(amount);
    //UpdateUI
    updateUI(currentAccount);
  }
  inputLoanAmount.value = "";
});

btnClose.addEventListener("click", function (e) {
  e.preventDefault();
  if (
    inputCloseUsername.value === currentAccount.username &&
    Number(inputClosePin.value) === currentAccount.pin
  ) {
    const index = accounts.findIndex(
      (acc) => acc.username === currentAccount.username
    );
    // Delete Account
    console.log(index);
    accounts.splice(index, 1);

    // Hide UI
    containerApp.style.opacity = 0;
  }
  inputCloseUsername.value = inputClosePin.value = "";
});
let sorted;
btnSort.addEventListener("click", function (e) {
  e.preventDefault();
  displayMovements(currentAccount.movements, !sorted);
  sorted = !sorted;
});

/////////////////////////////////////////////////
/////////////////////////////////////////////////
// LECTURES

// const currencies = new Map([
//   ['USD', 'United States dollar'],
//   ['EUR', 'Euro'],
//   ['GBP', 'Pound sterling'],
// ]);

// const movements = [200, 450, -400, 3000, -650, -130, 70, 1300];
/*
/////////////////////////////////////////////////
let arr = ['a', 'b', 'c', 'd', 'e'];
// SLICE METHOD
console.log(arr.slice(2)); // IT DOES'NT MUTATE THE ORGINAL ARRRAY
console.log(arr);

// SPLICE METHOD
console.log(arr.splice(2)); // IT MUTATE THE ORGINAL ARRAY
console.log(arr);

// REVERSE METHOD
arr = ['a', 'b', 'c', 'd', 'e'];
const arr2 = ['e', 'd', 'c', 'b', 'a'];
console.log(arr2.reverse()); //IT ALSO MUTATE THE ORIGINAL ARRAY
console.log(arr2);

// CONCAT METHOD
console.log(arr.concat(arr2)); // IT DOES'NT MUTATE THE ORIGNAL ARRAY

const movements = [200, 450, -400, 3000, -650, -130, 70, 1300];
for (const [i, movement] of movements.entries()) {
  if (movement > 0) {
    console.log(`Movement ${i + 1}: You Deposited ${movement} Cash`);
  } else {
    console.log(`Movement ${i + 1}: You Withdraw ${Math.abs(movement)} `);
  }
}
console.log('\n---- FOR EACH LOOP----'); // It works based on the Callback function
movements.forEach(function (mov, i) {
  if (mov > 0) {
    console.log(`Movement ${i + 1}: You Deposited ${mov} Cash`);
  } else {
    console.log(`Movement ${i + 1}: You Withdraw ${Math.abs(mov)} `);
  }
});

// Execute the forEach in Maps

const currencies = new Map([
  ['USD', 'United States dollar'],
  ['EUR', 'Euro'],
  ['GBP', 'Pound sterling'],
]);
currencies.forEach(function (value, key, map) {
  console.log(`${key} : ${value} `);
});

const checkDogs = function (dogsJulia, dogsKate) {
  const dogsJuliaCorrected = dogsJulia.slice();
  dogsJuliaCorrected.splice(0, 1);
  dogsJuliaCorrected.splice(-2);
  const dogs = dogsJuliaCorrected.concat(dogsKate);
  dogs.forEach(function (dog, i) {
    if (dog >= 3) {
      console.log(`Dog Number ${i + 1} is an adult, ${dog} years old :)`);
    } else {
      console.log(`Dog Number ${i + 1} is a puppy. ${dog} years old :(`);
    }
  });
};
checkDogs([3, 5, 2, 12, 7], [4, 1, 15, 8, 3]);

const movements = [200, 450, -400, 3000, -650, -130, 70, 1300];

const euroToUsd = 1.1;
const movmentsUsd = movements.map(function (mov) {
  return mov * euroToUsd;
});
console.log(movements);
console.log(movmentsUsd);
const movementDescription = movements.map(
  (mov, i) =>
    `Movement ${i + 1}: You ${mov > 0 ? 'Deposited' : 'WithDraw'} ${Math.abs(
      mov
    )}`
);
console.log(movementDescription);
// 
const movements = [200, 450, -400, 3000, -650, -130, 70, 1300];
const deposits = movements.filter(function (mov) {
  return mov > 0;
});
console.log(movements);
console.log(deposits);

const withdrawal = movements.filter(function (neg) {
  return neg < 0;
});
console.log(movements);
console.log(withdrawal);

const balance = movements.reduce(function (acc, cur, i, arr) {
  console.log(`Iteraton ${i} : ${acc}`);

  return acc + cur;
}, 0);
const movements = [200, 450, -400, 3000, -650, -130, 70, 1300];
const euroToUsd = 1.1;
const totalDepositsUSD = movements
  .filter(mov => mov > 0)
  .map(mov => mov * euroToUsd)
  .reduce((acc, mov) => acc + mov);
// console.log(totalDepositsUSD);
const firstWithDrawal = movements.find(mov => mov < 0);
// console.log(movements);
// console.log(firstWithDrawal);
const account = accounts.find(acc => acc.owner === 'Sarah Smith');
*/
const movements = [200, 450, -400, 3000, -650, -130, 70, 1300];

// const combine = movements.reduce(function (acc, rec) {
//   return acc + rec;
// });
// console.log(combine);

/////// SOME AND EVERY METHOD IN JS
// Checking the Equality
// console.log(movements.includes(-130));
// SOME METHOD
// But In This Condtion We Are Checking The Condition
// console.log(movements.some(mov => mov === -130));
const anyDeposits = movements.some((mov) => mov > 0);
// console.log(anyDeposits);

// EVERY METHOD
// console.log(movements.every(mov => mov > 0));

// FLAT AND FLATMAP METHOD

const accountmovements = accounts.map((acc) => acc.movements);
// console.log(accountmovements);
const allmovements = accountmovements.flat();
// console.log(allmovements);
const overallbalance = allmovements.reduce((acc, mov) => acc + mov, 0);
// console.log(overallbalance);

// ANOTHER METHOD USING FLAT' We can go deep flat also EX: movements.flat(depth parameter)'
const overallbalances = accounts
  .map((acc) => acc.movements)
  .flat()
  .reduce((acc, mov) => acc + mov, 0);
// console.log(overallbalances);

// ANOTHER METHOD USING FLATMAP 'The flatmap method doesn't have deep functionality'
const overallbalanceeff = accounts
  .flatMap((acc) => acc.movements)
  .reduce((acc, mov) => acc + mov, 0);
// console.log(overallbalanceeff);

// Multiple Ways of Creating the Array
const x = new Array(7);
// console.log(x);
// Using The 'From' Method
const y = Array.from({ length: 7 }, () => 1);
// console.log(y);

const currencies = new Map([
  ["USD", "United States dollar"],
  ["EUR", "Euro"],
  ["GBP", "Pound sterling"],
]);

// console.log(currencies);
