using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Enigma.PublicKey;
using Enigma.Utils;
using Enigma.WpfApp.Views.Dialogs;
using Enigma.Extensions;
using Microsoft.Win32;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace Enigma.WpfApp.ViewModels.Pages;

public class RsaPageViewModel : ObservableObject
{
    private readonly IContentDialogService _dialogService;
    private readonly IPublicKeyService _publicKeyService;

    public RsaPageViewModel(IContentDialogService dialogService,
        IPublicKeyServiceFactory publicKeyServiceFactory)
    {
        _dialogService = dialogService;
        _publicKeyService = publicKeyServiceFactory.CreateRsaService();
        
        GenerateKeyPairCommand = new AsyncRelayCommand(GenerateKeyPairAsync);
        LoadPublicKeyCommand = new AsyncRelayCommand(LoadPublicKeyAsync);
        LoadPrivateKeyCommand = new AsyncRelayCommand(LoadPrivateKeyAsync);
        LoadEncryptedPrivateKeyCommand = new AsyncRelayCommand(LoadEncryptedPrivateKeyAsync);
        SavePublicKeyCommand = new AsyncRelayCommand(SavePublicKeyAsync);
        SavePrivateKeyCommand = new AsyncRelayCommand(SavePrivateKeyAsync);
        SaveEncryptedPrivateKeyCommand = new AsyncRelayCommand(SaveEncryptedPrivateKeyAsync);
    }

    private string? _publicKey;
    public string? PublicKey
    {
        get => _publicKey;
        set => SetProperty(ref _publicKey, value);
    }
    
    private string? _privateKey;
    public string? PrivateKey
    {
        get => _privateKey;
        set => SetProperty(ref _privateKey, value);
    }

    private byte[] _inputData = [];
    public byte[] InputData
    {
        get => _inputData;
        set => SetProperty(ref _inputData, value);
    }
    
    public AsyncRelayCommand GenerateKeyPairCommand { get; }
    public AsyncRelayCommand LoadPublicKeyCommand { get; }
    public AsyncRelayCommand LoadPrivateKeyCommand { get; }
    public AsyncRelayCommand LoadEncryptedPrivateKeyCommand { get; }
    public AsyncRelayCommand SavePublicKeyCommand { get; }
    public AsyncRelayCommand SavePrivateKeyCommand { get; }
    public AsyncRelayCommand SaveEncryptedPrivateKeyCommand { get; }

    private async Task GenerateKeyPairAsync()
    {
        var keyGenerationDialog = new RsaKeyPairGenerationDialog();
        var dialog = new ContentDialog(_dialogService.GetDialogHost())
        {
            Title = "Generate RSA Key Pair",
            Content = keyGenerationDialog,
            PrimaryButtonText = "Generate",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };
        
        Binding primaryButtonBinding = new Binding(nameof(RsaKeyPairGenerationDialog.IsDataValid))
        {
            Source = keyGenerationDialog,
            Mode = BindingMode.OneWay
        };
        dialog.SetBinding(ContentDialog.IsPrimaryButtonEnabledProperty, primaryButtonBinding);
        
        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            PublicKey = "Please wait...";
            PrivateKey = "Please wait...";
            
            var keySize = keyGenerationDialog.KeySize;
            // string password = keyGenerationDialog.KeyPassword.Password;

            // await GenerateRsaKeyPairAsync(keySize);
            await Task.Run(async () => await GenerateRsaKeyPairAsync(keySize));
        }
    }

    private async Task GenerateRsaKeyPairAsync(int keySize)
    {
        var keyPair = _publicKeyService.GenerateKeyPair(keySize);
        using var pubMs = new MemoryStream();
        PemUtils.SaveKey(keyPair.Public, pubMs);
        PublicKey = pubMs.ToArray().GetUtf8String();
            
        using var priMs = new MemoryStream();
        PemUtils.SaveKey(keyPair.Private, priMs);
        PrivateKey = priMs.ToArray().GetUtf8String();

        await Task.CompletedTask;
    }

    private async Task LoadPublicKeyAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Load public key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (dialog.ShowDialog() == true)
        {
            await using var input = new FileStream(dialog.FileName, FileMode.Open, FileAccess.Read);
            using var reader = new StreamReader(input);
            PublicKey = await reader.ReadToEndAsync();
        }
    }

    private async Task LoadPrivateKeyAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Load public key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (dialog.ShowDialog() == true)
        {
            await using var input = new FileStream(dialog.FileName, FileMode.Open, FileAccess.Read);
            using var reader = new StreamReader(input);
            PrivateKey = await reader.ReadToEndAsync();
        }
    }

    private async Task LoadEncryptedPrivateKeyAsync()
    {
        var fileDialog = new OpenFileDialog
        {
            Title = "Load public key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (fileDialog.ShowDialog() != true)
            return;
        
        var passwordDialog = new PasswordDialog();
        var dialog = new ContentDialog(_dialogService.GetDialogHost())
        {
            Title = "Enter key password",
            Content = passwordDialog,
            PrimaryButtonText = "Validate",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };
        
        Binding primaryButtonBinding = new Binding(nameof(RsaKeyPairGenerationDialog.IsDataValid))
        {
            Source = passwordDialog,
            Mode = BindingMode.OneWay
        };
        dialog.SetBinding(ContentDialog.IsPrimaryButtonEnabledProperty, primaryButtonBinding);
        
        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            var password = passwordDialog.KeyPassword.Password;
            await using var input = new FileStream(fileDialog.FileName, FileMode.Open, FileAccess.Read);
            // TODO: continue after fix
        }
    }

    private async Task SavePublicKeyAsync()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save public key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (dialog.ShowDialog() == true)
        {
            await using var output = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write);
            await using var writer = new StreamWriter(output, Encoding.UTF8);
            await writer.WriteAsync(PublicKey);
        }
    }

    private async Task SavePrivateKeyAsync()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save private key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (dialog.ShowDialog() == true)
        {
            await using var output = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write);
            await using var writer = new StreamWriter(output, Encoding.UTF8);
            await writer.WriteAsync(PrivateKey);
        } 
    }

    private async Task SaveEncryptedPrivateKeyAsync()
    {
        
    }
}