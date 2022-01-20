// show and hide spinning green circle whilst scanning
function scanning() {
    let spinnerBox = document.getElementById('spinner-box')
    let dataBox = document.getElementById('data-box')
    dataBox.setAttribute("class", "not-visible")
    spinnerBox.setAttribute("class", "visible")
}

// search function for tables by filtering table rows (e.g. <tbody id=myTable>, <input id="myInput">)
function search() {
    $(document).ready(function(){
      $("#myInput").on("keyup", function() {
        let value = $(this).val().toLowerCase();
        $("#myTable tr").filter(function() {
          $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
      });
    });
}