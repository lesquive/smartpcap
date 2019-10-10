window.addEventListener("DOMContentLoaded", function(e) {
    var myHilitor2 = new Hilitor("container-fluid");
    myHilitor2.setMatchType("left");
    document.getElementById("searchbar").addEventListener("keyup", function(e) {
      myHilitor2.apply(this.value);
    }, false);
  }, false);


document.addEventListener('DOMContentLoaded', () => {
    const btnHide = document.getElementById('submitbutton');
    btnHide.hidden = true;

    document.getElementById("submitbutton").onclick = function() {myFunction()};

    function myFunction() {
        document.getElementById("container-fluid").innerHTML = '<div class="body"><span><span></span><span></span><span></span><span></span></span><div class="base"><span></span><div class="face"></div></div></div><div class="longfazers"><span></span><span></span><span></span><span></span></div><h1>Analyzing Packet Capture...</h1>';
    }

});

document.addEventListener('DOMContentLoaded', () => {

    document.getElementById("view_all_packets").onclick= function() {myFunction()};

    function myFunction() {
        document.getElementById("container-fluid").innerHTML = '<div class="body"><span><span></span><span></span><span></span><span></span></span><div class="base"><span></span><div class="face"></div></div></div><div class="longfazers"><span></span><span></span><span></span><span></span></div><h1>Analyzing Packet Capture...</h1>';
    }

});

document.addEventListener('DOMContentLoaded', () => {

    document.getElementById("scroll-to-top-button").onclick= function() {topFunction()};

    //Get the button:
    mybutton = document.getElementById("scroll-to-top-button");

    // When the user scrolls down 20px from the top of the document, show the button
    window.onscroll = function() {scrollFunction()};

    function scrollFunction() {
    if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
        mybutton.style.display = "block";
    } else {
        mybutton.style.display = "none";
    }
    }

    // When the user clicks on the button, scroll to the top of the document
    function topFunction() {
    document.body.scrollTop = 0; // For Safari
    document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
    }
});
