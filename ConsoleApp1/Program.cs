using System.Threading.Tasks;
using System;

namespace ConsoleApp1;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        await Task.CompletedTask;

        try
        {
            
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}