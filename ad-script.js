"use strict";

///////////////////////////////////////
// Modal window

const modal = document.querySelector(".modal");
const overlay = document.querySelector(".overlay");
const btnCloseModal = document.querySelector(".btn--close-modal");
const btnsOpenModal = document.querySelectorAll(".btn--show-modal");
const btnScrollTo = document.querySelector(".btn--scroll-to");
const section1 = document.querySelector("#section--1");
const tabs = document.querySelectorAll(".operations__tab");
const tabsContainer = document.querySelector(".operations__tab-container");
const tabsContent = document.querySelectorAll(".operations__content");
const nav = document.querySelector(".nav");

const openModal = function (e) {
  e.preventDefault();
  modal.classList.remove("hidden");
  overlay.classList.remove("hidden");
};

const closeModal = function () {
  modal.classList.add("hidden");
  overlay.classList.add("hidden");
};

btnsOpenModal.forEach((btn) => {
  btn.addEventListener("click", openModal);
});

// for (let i = 0; i < btnsOpenModal.length; i++)
//   btnsOpenModal[i].addEventListener('click', openModal);

btnCloseModal.addEventListener("click", closeModal);
overlay.addEventListener("click", closeModal);

document.addEventListener("keydown", function (e) {
  if (e.key === "Escape" && !modal.classList.contains("hidden")) {
    closeModal();
  }
});

///////////////////
//Button Scrolling
btnScrollTo.addEventListener("click", function (e) {
  const s1coords = section1.getBoundingClientRect();
  // console.log(s1coords);

  // console.log(e.target.getBoundingClientRect());
  // console.log('Current Scroll(X/Y', window.pageXOffset, pageYOffset);
  // console.log(
  //   'Height and Width Of the viewport:',
  //   document.documentElement.clientHeight,
  //   document.documentElement.clientWidth
  // );
  window.scrollTo(s1coords.left, s1coords.top);
  // console.log(window.scrollTo(s1coords.left, s1coords.top));
  // window.scrollTo({
  //   left: s1coords.left,
  //   top: s1coords.top,
  //   behavior: 'smooth',
  // });
  section1.scrollIntoView({ behavior: "smooth" });
});

/////////////////////
//Page Navigation

// document.querySelectorAll('.nav__link').forEach(function (el) {
//   el.addEventListener('click', function (e) {
//     e.preventDefault();
//     const id = this.getAttribute('href');
//     document.querySelector(id).scrollIntoView({ behavior: 'smooth' });
//   });
// });// In this above solution is not efficent Because it each copies for each click

// More Effecient Ways
document.querySelector(".nav__links").addEventListener("click", function (e) {
  e.preventDefault();
  // Matching Stragey
  if (e.target.classList.contains("nav__link")) {
    const id = e.target.getAttribute("href");
    // document.querySelector(id).scrollIntoView({ behavior: 'smooth' });
    //   }
  }
});

// Tabbed Component
tabsContainer.addEventListener("click", function (e) {
  const clicked = e.target.closest(".operations__tab");
  // console.log(clicked);
  //Guard Clause
  if (!clicked) return;

  // Remove the active classes
  tabs.forEach((t) => t.classList.remove("operations__tab--active"));
  tabsContent.forEach((c) => c.classList.remove("operations__content--active"));

  //Activate tabs
  clicked.classList.add("operations__tab--active");

  //Activate Content Area
  // console.log(clicked.dataset.tab);
  document
    .querySelector(`.operations__content--${clicked.dataset.tab}`)
    .classList.add("operations__content--active");
});

//Menu Fade Animation
const handleHover = function (e) {
  if (e.target.classList.contains("nav__link")) {
    const link = e.target;
    const sibilings = link.closest(".nav").querySelectorAll(".nav__link");
    const logo = link.closest(".nav").querySelector("img");
    sibilings.forEach((el) => {
      if (el != link) el.style.opacity = this;
    });
    logo.style.opacity = this;
  }
};
nav.addEventListener("mouseover", handleHover.bind(0.5));
nav.addEventListener("mouseout", handleHover.bind(1));

// //Sticky Navigation
// const initialCoords = section1.getBoundingClientRect();

// window.addEventListener('scroll', function () {
//   // console.log(window.scrollY);// If we getting the that value using if else condtion is not gone work because the scrollY value change Based on the cureent view port
//   // console.log(e);

//   // Not Effiect  Way
//   if (window.scrollY > initialCoords.top) nav.classList.add('sticky');
//   else nav.classList.remove('sticky');
// });

// More Efficent Way Using Intersection observer API

// const obsCallback = function (entries) {
//   entries.forEach(entry => {
//     console.log(entry);
//   });
// };

// const obsOptions = {
//   root: null,
//   threshold: 0.1,
// };
// const observer = new IntersectionObserver(obsCallback, obsOptions);
// observer.observe(section1);
const header = document.querySelector(".header");
const navHeight = nav.getBoundingClientRect().height;
// console.log(navHeight);

const stickyNav = function (entries) {
  const [entry] = entries;

  if (!entry.isIntersecting) nav.classList.add("sticky");
  else nav.classList.remove("sticky");
};
const headerObserver = new IntersectionObserver(stickyNav, {
  root: null,
  threshold: 0,
  rootMargin: `-${navHeight}px`,
});
headerObserver.observe(header);

//Reavel Section
const allSections = document.querySelectorAll(".section");
const revealSection = function (entries, observer) {
  const [entry] = entries;
  if (!entry.isIntersecting) return;
  entry.target.classList.remove("section--hidden");
  observer.unobserve(entry.target);
};

const sectionObserver = new IntersectionObserver(revealSection, {
  root: null,
  threshold: 0.15,
});

allSections.forEach(function (section) {
  sectionObserver.observe(section);
  section.classList.add("section--hidden");
});

// Lazy Image Loading Functionality

const imgTargets = document.querySelectorAll("img[data-src]");

const loadImg = function (entries, observer) {
  const [entry] = entries;
  // console.log(entry);
  if (!entry.isIntersecting) return;
  entry.target.src = entry.target.dataset.src;
  entry.target.addEventListener("load", function () {
    entry.target.classList.remove("lazy-img");
  });
  observer.unobserve(entry.target);
};

const imgObserver = new IntersectionObserver(loadImg, {
  root: null,
  threshold: 1,
  rootMargin: "200px",
});

imgTargets.forEach((img) => imgObserver.observe(img));

//Sliders Components

const slides = document.querySelectorAll(".slide");
const btnLeft = document.querySelector(".slider__btn--left");
const btnRight = document.querySelector(".slider__btn--right");
const sliders = document.querySelector(".slider");
const dotContainer = document.querySelector(".dots");
const maxSlider = slides.length - 1;
let curSlide = 0;

const createDots = function () {
  slides.forEach(function (_, i) {
    dotContainer.insertAdjacentHTML(
      "beforeend",
      `<button class="dots__dot" data-slide="${i}"></button>`
    );
  });
};
createDots();
const activateDots = function (slide) {
  document
    .querySelectorAll(".dots__dot")
    .forEach((dot) => dot.classList.remove("dots__dot--active"));
  document
    .querySelector(
      `.dots__dot[data-slide="${slide}"]
      `
    )
    .classList.add("dots__dot--active");
};
activateDots(0);
const goToSlide = function (slide) {
  slides.forEach(
    (s, i) => (s.style.transform = `translateX(${100 * (i - curSlide)}%)`)
  );
};
// sliders.style.transform = 'scale(0.4) translateX(-800px)';
// sliders.style.overflow = 'visible';

goToSlide(0);

//Next Slide Func
const nextSlide = function () {
  if (curSlide == maxSlider) {
    curSlide = 0;
  } else {
    curSlide++;
  }
  goToSlide(curSlide);
  activateDots(curSlide);
};
const prevSlide = function () {
  if (curSlide === 0) {
    curSlide = maxSlider;
  } else {
    curSlide--;
  }
  goToSlide(curSlide);
  activateDots(curSlide);
};
btnRight.addEventListener("click", nextSlide);
btnLeft.addEventListener("click", prevSlide);

// Make the slide Functionality In key press Event
document.addEventListener("keydown", function (e) {
  // console.log(e);

  if (e.key === "ArrowLeft") prevSlide();
  e.key === "ArrowRight" && nextSlide();
});

dotContainer.addEventListener("click", (e) => {
  // console.log(e.target);

  if (e.target.classList.contains("dots__dot")) {
    const { slide } = e.target.dataset; // Destructuring
    goToSlide(slide);
    activateDots(slide);
  }
});

document.addEventListener("DOMContentLoaded", function (e) {
  // console.log('HTML and Dom Tree loaded', e);
});
///////////////////////////////////
///////////////////////////////////
////////////////
/*

// Creating and inserting the elements

const header = document.querySelector('.header');
const message = document.createElement('div');

message.classList.add('cookie-message');

// message.innerHTML =
//   'We use cooking for improve the functionality for the webpage.<button class= " btn btn--close-cookie">Got It!</button>';
// // header.prepend(message);
// header.append(message); // We need the same elements in multiple places...
// header.append(message.cloneNode(true)); // We need the same elements in multiple places...

//Delete the Elements

// document
//   .querySelector('.btn--close-cookie')
//   .addEventListener('click', function () {
//     message.remove();
//     // message.parentElement.removeChild(message) Newer Way of delete the element travsing the DOM
//   });

//Styles

message.style.backgroundColor = '#37383d';
message.style.width = '120%';

console.log(getComputedStyle(message).color);
console.log(getComputedStyle(message).height);

message.style.height =
  Number.parseFloat(getComputedStyle(message).height) + 30 + 'px';

//Data Attrs

const logo = document.querySelector('.nav__logo');
// console.log(logo.dataset.versionNumber);

// Coordination Points

const btnScrollTo = document.querySelector('.btn--scroll-to');
const section1 = document.querySelector('#section--1');

btnScrollTo.addEventListener('click', function (e) {
  const s1coords = section1.getBoundingClientRect();
  // console.log(s1coords);

  // console.log(e.target.getBoundingClientRect());
  // console.log('Current Scroll(X/Y', window.pageXOffset, pageYOffset);
  // console.log(
  //   'Height and Width Of the viewport:',
  //   document.documentElement.clientHeight,
  //   document.documentElement.clientWidth
  // );
  window.scrollTo(s1coords.left, s1coords.top);
  // console.log(window.scrollTo(s1coords.left, s1coords.top));
  // window.scrollTo({
  //   left: s1coords.left,
  //   top: s1coords.top,
  //   behavior: 'smooth',
  // });
  section1.scrollIntoView({ behavior: 'smooth' });
});

const h1 = document.querySelector('h1');
// h1.addEventListener('mouseenter', function () {
//   h1.textContent = 'Hi Rasith Your Are The Great JavaScript Developer!!';
// });
// const h1alert = function (e) {
//   alert('Hi Rasith Your Are The Great JavaScript Developer!!');
//   h1.removeEventListener('mouseenter', h1alert);
// };
// h1.addEventListener('mouseenter', h1alert);

const sec_1 = document.querySelector('.header');
// sec_1.addEventListener('click', () => {
//   alert('hello world :)');
// });

// Generating the Random Color

const randomInt = (min, max) =>
  Math.floor(Math.random() * (max - min + 1) + min);

const randomColor = () =>
  `rgb(${randomInt(0, 255)},${randomInt(0, 255)},${randomInt(0, 255)})`;
// console.log(randomColor(0, 255));

// sec_1.style.backgroundColor = String(randomColor(0, 255));

//Going Downwards :Child
console.log(h1.querySelectorAll('.highlight'));
console.log(h1.childNodes);
console.log(h1.children);

h1.firstElementChild.style.color = 'white';
h1.lastElementChild.style.color = 'orangered';

// Going Upward

console.log(h1.parentNode);
h1.closest('.header').style.background = 'var(--gradient-primary)';

// Going Silbling

const h1 = document.querySelector('h1');

console.log(h1.previousElementSibling);
console.log(h1.nextElementSibling);
*/
