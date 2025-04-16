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
using Org.BouncyCastle.Crypto;
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
        SavePublicKeyCommand = new AsyncRelayCommand(SavePublicKeyAsync, () => PublicKey is not null);
        SavePrivateKeyCommand = new AsyncRelayCommand(SavePrivateKeyAsync, () => PrivateKey is not null);
        SaveEncryptedPrivateKeyCommand = new AsyncRelayCommand(SaveEncryptedPrivateKeyAsync, () => PrivateKey is not null);
    }

    private AsymmetricKeyParameter? _publicKey;
    public AsymmetricKeyParameter? PublicKey
    {
        get => _publicKey;
        set
        {
            if (SetProperty(ref _publicKey, value))
            {
                SavePublicKeyCommand.NotifyCanExecuteChanged();
                
                if (value is null) return;
                using var pubMs = new MemoryStream();
                PemUtils.SaveKey(value, pubMs);
                PublicKeyStr = pubMs.ToArray().GetUtf8String(); 
            }
        }
    }

    private string? _publicKeyStrStr;
    public string? PublicKeyStr
    {
        get => _publicKeyStrStr;
        set => SetProperty(ref _publicKeyStrStr, value);
    }
    
    private AsymmetricKeyParameter? _privateKey;
    public AsymmetricKeyParameter? PrivateKey
    {
        get => _privateKey;
        set
        {
            if (SetProperty(ref _privateKey, value))
            {
                SavePrivateKeyCommand.NotifyCanExecuteChanged();
                SaveEncryptedPrivateKeyCommand.NotifyCanExecuteChanged();
                
                if (value is null) return;
                using var priMs = new MemoryStream();
                PemUtils.SaveKey(value, priMs);
                PrivateKeyStr = priMs.ToArray().GetUtf8String(); 
            }
        }
    }
    
    private string? _privateKeyStrStr;
    public string? PrivateKeyStr
    {
        get => _privateKeyStrStr;
        set => SetProperty(ref _privateKeyStrStr, value);
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
        
        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Primary)
        {
            PublicKeyStr = "Please wait...";
            PrivateKeyStr = "Please wait...";
            
            var keySize = keyGenerationDialog.KeySize;
            await Task.Run(async () => await GenerateRsaKeyPairAsync(keySize));
        }
    }

    private async Task GenerateRsaKeyPairAsync(int keySize)
    {
        var keyPair = _publicKeyService.GenerateKeyPair(keySize);
        PublicKey = keyPair.Public;
        PrivateKey = keyPair.Private;
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
            PublicKey = PemUtils.LoadKey(input);
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
            PrivateKey = PemUtils.LoadKey(input);
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
            PrivateKey = PemUtils.LoadPrivateKey(input, password);
        }
    }

    private async Task SavePublicKeyAsync()
    {
        if (PublicKey is null)
            return;
        
        var dialog = new SaveFileDialog
        {
            Title = "Save public key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (dialog.ShowDialog() == true)
        {
            await using var output = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write);
            PemUtils.SaveKey(PublicKey, output);
        }
    }

    private async Task SavePrivateKeyAsync()
    {
        if (PrivateKey is null)
            return;
        
        var dialog = new SaveFileDialog
        {
            Title = "Save private key",
            Filter = "PEM Files (*.pem)|*.pem"
        };
        if (dialog.ShowDialog() == true)
        {
            await using var output = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write);
            PemUtils.SaveKey(PrivateKey, output);
        } 
    }

    private async Task SaveEncryptedPrivateKeyAsync()
    {
        if (PrivateKey is null)
            return;
        
        var fileDialog = new SaveFileDialog
        {
            Title = "Save public key",
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
            await using var output = new FileStream(fileDialog.FileName, FileMode.Create, FileAccess.Write);
            PemUtils.SavePrivateKey(PrivateKey, output, password);
        } 
    }
}