let sec = document.getElementById('sec');
let start = document.getElementById('start');
let seconds = 0;
let timerStopped = null;
function increaseSeconds(){
    seconds++;
    sec.innerText = seconds;
};


changeSeconds = start.addEventListener('click', function change(){
    // condition to not start multiple timers
    if  (!timerStopped){
    timerStopped = setInterval(increaseSeconds, 1000);
    };
});
let pause = document.getElementById('pause');
pause.addEventListener('click', function stop(){
    clearInterval(timerStopped);
    timerStopped = null
});