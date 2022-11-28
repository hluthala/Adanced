#pragma checksum "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4ec9174fcb044ad777dc9b762733a34f580400ab"
// <auto-generated/>
#pragma warning disable 1591
#pragma warning disable 0414
#pragma warning disable 0649
#pragma warning disable 0169

namespace Advanced.Blazor.Forms
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
#nullable restore
#line 1 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components.Forms;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components.Routing;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.AspNetCore.Components.Web;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.JSInterop;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Microsoft.EntityFrameworkCore;

#line default
#line hidden
#nullable disable
#nullable restore
#line 7 "/Users/jdevelopa/Documents/GitHub/Advanced/_Imports.razor"
using Advanced.Models;

#line default
#line hidden
#nullable disable
    [Microsoft.AspNetCore.Components.LayoutAttribute(typeof(EmptyLayout))]
    [Microsoft.AspNetCore.Components.RouteAttribute("/forms")]
    [Microsoft.AspNetCore.Components.RouteAttribute("/forms/list")]
    public partial class List : OwningComponentBase<DataContext>
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
        }
        #pragma warning restore 1998
#nullable restore
#line 46 "/Users/jdevelopa/Documents/GitHub/Advanced/Blazor/Forms/List.razor"
       

    public DataContext Context => Service;

    public IEnumerable<Person> People { get; set; } = Enumerable.Empty<Person>();

    protected async override Task OnInitializedAsync() {
        await UpdateData();
    }

    private IQueryable<Person> Query => Context.People.Include(p => p.Department)
            .Include(p => p.Location);

    private async Task UpdateData(IQueryable<Person> query = null) =>
        People = await (query ?? Query).ToListAsync<Person>();

    string GetEditUrl(long id) => $"/forms/edit/{id}";
    string GetDetailsUrl(long id) => $"/forms/details/{id}";

    public async Task HandleDelete(Person p) {
        Context.Remove(p);
        await Context.SaveChangesAsync();
        await UpdateData();
    }

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591