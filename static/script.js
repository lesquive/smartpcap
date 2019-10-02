
document.addEventListener('DOMContentLoaded', () => {
    const btnHide = document.getElementById('sumbit-button-id');
    btnHide.hidden = true;

    document.getElementById("sumbit-button-id").onclick = function() {myFunction()};

    function myFunction() {
        document.getElementById("container-fluid").innerHTML = '<div class="body"><span><span></span><span></span><span></span><span></span></span><div class="base"><span></span><div class="face"></div></div></div><div class="longfazers"><span></span><span></span><span></span><span></span></div><h1>Analyzing Packet Capture...</h1>';
    }
    
});


